package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/lemito/CryptoMAI/proto"
)

type ChatService struct {
	pb.UnimplementedChatServiceServer
	db *sql.DB
}

func NewChatService(db *sql.DB) *ChatService {
	return &ChatService{
		db: db,
	}
}

func (s *ChatService) CreateChat(ctx context.Context, req *pb.CreateChatRequest) (*pb.ChatInfo, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.validateCreateChatRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.validateContact(ctx, authContext.Username, req.ContactUsername); err != nil {
		return nil, err
	}

	newChat, err := s.createNewChatInDB(ctx, authContext.Username, req)
	if err != nil {
		return nil, status.Error(codes.Internal, "не удалось создать чат: "+err.Error())
	}

	return s.convertChatToChatInfo(newChat), nil
}

func (s *ChatService) validateCreateChatRequest(req *pb.CreateChatRequest) error {
	if req.ContactUsername == "" {
		return fmt.Errorf("имя пользователя контакта обязательно")
	}
	if req.EncryptionParams == nil {
		return fmt.Errorf("параметры шифрования обязательны")
	}
	if len(req.EncryptionParams.ChatIv) == 0 {
		return fmt.Errorf("IV чата обязателен")
	}
	if req.InitiatorParams == nil {
		return fmt.Errorf("параметры DH обязательны")
	}
	if req.InitiatorParams.Prime == nil || req.InitiatorParams.Generator == nil || req.InitiatorParams.PublicKey == nil {
		return fmt.Errorf("неполные параметры DH")
	}
	return nil
}

func (s *ChatService) validateContact(ctx context.Context, username, contactUsername string) error {
	var exists bool
	err := s.db.QueryRowContext(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM contacts c
            JOIN users u1 ON c.user_id = u1.id
            JOIN users u2 ON c.contact_id = u2.id
            WHERE u1.username = $1 AND u2.username = $2 AND c.status = 'accepted'
        )`,
		username, contactUsername).Scan(&exists)

	if err != nil {
		return status.Errorf(codes.Internal, "не удалось проверить контакт: %v", err)
	}
	if !exists {
		return status.Error(codes.NotFound, "контакт не найден или не подтвержден")
	}
	return nil
}

func (s *ChatService) createNewChatInDB(ctx context.Context, initiatorUsername string, req *pb.CreateChatRequest) (*Chat, error) {
	var existingChatID string
	err := s.db.QueryRowContext(ctx, `
        SELECT id FROM chats 
        WHERE initiator_username = $1 
        AND participant_username = $2 
        AND algorithm = $3 
        AND mode = $4 
        AND padding = $5 
        AND base_iv = $6 
        AND is_active = true`,
		initiatorUsername, req.ContactUsername,
		req.EncryptionParams.Algorithm.String(),
		req.EncryptionParams.Mode.String(),
		req.EncryptionParams.Padding.String(),
		req.EncryptionParams.ChatIv).Scan(&existingChatID)

	if err == nil {
		return nil, fmt.Errorf("такой чатик уже есть")
	} else if err != sql.ErrNoRows {
		return nil, fmt.Errorf("ошибка: %v", err)
	}

	initiatorDH := DHParams{
		Prime:     req.InitiatorParams.Prime,
		Generator: req.InitiatorParams.Generator,
		PublicKey: req.InitiatorParams.PublicKey,
	}
	initiatorDHJSON, err := json.Marshal(initiatorDH)
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать параметры DH: %v", err)
	}

	chatID := uuid.New().String()
	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
        INSERT INTO chats (id, initiator_username, participant_username, algorithm, mode, padding, 
                          base_iv, initiator_dh_params, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		chatID, initiatorUsername, req.ContactUsername,
		req.EncryptionParams.Algorithm.String(),
		req.EncryptionParams.Mode.String(),
		req.EncryptionParams.Padding.String(),
		req.EncryptionParams.ChatIv,
		initiatorDHJSON,
		true, now,
	)
	if err != nil {
		return nil, fmt.Errorf("не удалось вставить чат: %v", err)
	}

	users := []string{initiatorUsername, req.ContactUsername}
	for _, username := range users {
		_, err = tx.ExecContext(ctx, `
            INSERT INTO user_chats (user_id, chat_id, username, is_active, joined_at)
            SELECT u.id, $1, u.username, true, $2
            FROM users u WHERE u.username = $3`,
			chatID, now, username)
		if err != nil {
			return nil, fmt.Errorf("не удалось добавить пользователя %s в чат: %v", username, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("не удалось зафиксировать транзакцию: %v", err)
	}

	return &Chat{
		ID:          chatID,
		Initiator:   initiatorUsername,
		Participant: req.ContactUsername,
		Algorithm:   req.EncryptionParams.Algorithm,
		Mode:        req.EncryptionParams.Mode,
		Padding:     req.EncryptionParams.Padding,
		BaseIV:      req.EncryptionParams.ChatIv,
		InitiatorDH: initiatorDH,
		PeerDH:      nil,
		IsActive:    true,
		CreatedAt:   now,
	}, nil
}

func (s *ChatService) JoinChat(ctx context.Context, req *pb.JoinChatRequest) (*pb.CommonResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "ID чата обязателен")
	}
	if req.PeerParams == nil {
		return nil, status.Error(codes.InvalidArgument, "параметры DH обязательны")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var participantUsername string
	err = tx.QueryRowContext(ctx, `
        SELECT participant_username FROM chats 
        WHERE id = $1 AND is_active = true`,
		req.ChatId).Scan(&participantUsername)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "активный чат не найден")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось найти чат: %v", err)
	}

	if participantUsername != authContext.Username {
		return nil, status.Error(codes.PermissionDenied, "вы не являетесь участником этого чата")
	}

	var alreadyJoined bool
	err = tx.QueryRowContext(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM user_chats 
            WHERE chat_id = $1 AND username = $2 AND is_active = true
        )`, req.ChatId, authContext.Username).Scan(&alreadyJoined)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "ошибка: %v", err)
	}
	if alreadyJoined {
		return nil, status.Error(codes.AlreadyExists, "вы уже находитесь в этом чате")
	}

	peerDH := DHParams{
		Prime:     req.PeerParams.Prime,
		Generator: req.PeerParams.Generator,
		PublicKey: req.PeerParams.PublicKey,
	}
	peerDHJSON, err := json.Marshal(peerDH)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось сериализовать параметры DH: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
        UPDATE chats SET peer_dh_params = $1 
        WHERE id = $2`,
		peerDHJSON, req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось обновить чат: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
        UPDATE user_chats SET is_active = true, joined_at = $1 
        WHERE chat_id = $2 AND username = $3`,
		time.Now(), req.ChatId, authContext.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось обновить информацию о чате пользователя: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось зафиксировать транзакцию: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Успешно зашел в чат",
	}, nil
}

func (s *ChatService) CloseChat(ctx context.Context, req *pb.CloseChatRequest) (*pb.CommonResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "ID чата обязателен")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var initiatorUsername string
	err = tx.QueryRowContext(ctx, `
        SELECT initiator_username FROM chats 
        WHERE id = $1 AND is_active = true`,
		req.ChatId).Scan(&initiatorUsername)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "активный чат не найден")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось найти чат: %v", err)
	}

	if initiatorUsername != authContext.Username {
		return nil, status.Error(codes.PermissionDenied, "только инициатор чата может закрыть чат")
	}

	_, err = tx.ExecContext(ctx, `
        UPDATE chats SET is_active = false 
        WHERE id = $1`,
		req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось закрыть чат: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
        UPDATE user_chats SET is_active = false, left_at = $1 
        WHERE chat_id = $2`,
		time.Now(), req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось обновить информацию о чатах пользователей: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось зафиксировать транзакцию: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Чат закрыт успешно",
	}, nil
}

func (s *ChatService) startChatCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, _ := s.db.ExecContext(ctx,
			"DELETE FROM chats WHERE is_active = false")
		cancel()
		cnt, err := result.RowsAffected()
		if err != nil {
			log.Printf("Ошибка очистки чатов: %v", err)
		}
		result, _ = s.db.ExecContext(ctx,
			"DELETE FROM user_chats WHERE is_active = false")
		log.Printf("Очищено %d неактивных чатов", cnt)
	}
}

func (s *ChatService) LeaveChat(ctx context.Context, req *pb.CloseChatRequest) (*pb.CommonResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "ID чата обязателен")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var user bool
	err = tx.QueryRowContext(ctx, `
		SELECT is_active FROM user_chats 
		WHERE chat_id = $1 AND username = $2`,
		req.ChatId, authContext.Username).Scan(&user)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "вы не являетесь участником этого чата")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось найти чат пользователя: %v", err)
	}

	if !user {
		return &pb.CommonResponse{
			Success: false,
			Message: "Вы уже покинули этот чат",
		}, nil
	}

	now := time.Now()
	
	_, err = tx.ExecContext(ctx, `
		UPDATE user_chats SET is_active = false, left_at = $1 
		WHERE chat_id = $2 AND username = $3`,
		now, req.ChatId, authContext.Username)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось покинуть чат: %v", err)
	}

	var nowUsers int
	err = tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_chats 
		WHERE chat_id = $1 AND is_active = true`,
		req.ChatId).Scan(&nowUsers)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось проверить активных участников: %v", err)
	}

	if nowUsers == 0 {
		_, err = tx.ExecContext(ctx, `
			DELETE FROM user_chats WHERE chat_id = $1`,
			req.ChatId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось удалить записи пользователей: %v", err)
		}

		_, err = tx.ExecContext(ctx, `
			DELETE FROM chats WHERE id = $1`,
			req.ChatId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось удалить чат: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось закоммитить транзакцию: %v", err)
	}

	msg := "Вы вышли из чата"
	if nowUsers == 0 {
		msg = "Чат удален, так как в нем не осталось участников"
	}

	return &pb.CommonResponse{
		Success: true,
		Message: msg,
	}, nil
}

func (s *ChatService) GetActiveChats(empty *emptypb.Empty, stream pb.ChatService_GetActiveChatsServer) error {
	ctx := stream.Context()
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return err
	}

	log.Printf("GetActiveChats stream started for user: %s", authContext.Username)

	chats, err := s.getcurActiveChats(ctx, authContext.Username)
	if err != nil {
		return err
	}

	for _, chat := range chats {
		chatInfo := s.convertChatToChatInfo(chat)
		if err := stream.Send(chatInfo); err != nil {
			return err
		}
	}

	<-ctx.Done()
	log.Printf("Поток завершен для: %s", authContext.Username)
	return ctx.Err()
}

func (s *ChatService) getcurActiveChats(ctx context.Context, username string) (map[string]*Chat, error) {
	chats := make(map[string]*Chat)

	rows, err := s.db.QueryContext(ctx, `
        SELECT c.id, c.initiator_username, c.participant_username, c.algorithm, c.mode, c.padding,
               c.base_iv, c.initiator_dh_params, c.peer_dh_params, c.is_active, c.created_at
        FROM chats c
        JOIN user_chats uc ON c.id = uc.chat_id
        WHERE uc.username = $1 AND uc.is_active = true AND c.is_active = true
        ORDER BY c.created_at DESC`,
		username)

	if err != nil {
		return nil, fmt.Errorf("ошибка: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		chat, err := s.scanChatFromRow(rows)
		if err != nil {
			log.Printf("ошибка: %v", err)
			continue
		}
		chats[chat.ID] = chat
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка: %v", err)
	}

	return chats, nil
}

func (s *ChatService) scanChatFromRow(rows *sql.Rows) (*Chat, error) {
	var chat Chat
	var initiatorDHJSON, peerDHJSON []byte
	var algorithmStr, modeStr, paddingStr string

	err := rows.Scan(
		&chat.ID, &chat.Initiator, &chat.Participant, &algorithmStr, &modeStr, &paddingStr,
		&chat.BaseIV, &initiatorDHJSON, &peerDHJSON, &chat.IsActive, &chat.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	chat.Algorithm = pb.EncryptionAlgorithm(pb.EncryptionAlgorithm_value[algorithmStr])
	chat.Mode = pb.EncryptionMode(pb.EncryptionMode_value[modeStr])
	chat.Padding = pb.PaddingMode(pb.PaddingMode_value[paddingStr])

	if err := json.Unmarshal(initiatorDHJSON, &chat.InitiatorDH); err != nil {
		return nil, fmt.Errorf("не удалось десериализовать параметры DH инициатора: %v", err)
	}

	if len(peerDHJSON) > 0 {
		var peerDH DHParams
		if err := json.Unmarshal(peerDHJSON, &peerDH); err != nil {
			return nil, fmt.Errorf("не удалось десериализовать параметры DH пира: %v", err)
		}
		chat.PeerDH = &peerDH
	}

	return &chat, nil
}

func (s *ChatService) convertChatToChatInfo(chat *Chat) *pb.ChatInfo {
	chatInfo := &pb.ChatInfo{
		ChatId:       chat.ID,
		Participants: []string{chat.Initiator, chat.Participant},
		EncryptionParams: &pb.EncryptionParameters{
			Algorithm: chat.Algorithm,
			Mode:      chat.Mode,
			Padding:   chat.Padding,
			ChatIv:    chat.BaseIV,
		},
		PeerParams: &pb.DHParameters{
			Prime:     chat.InitiatorDH.Prime,
			Generator: chat.InitiatorDH.Generator,
			PublicKey: chat.InitiatorDH.PublicKey,
		},
		IsActive: chat.IsActive,
	}

	if chat.PeerDH != nil {
		chatInfo.PeerParams = &pb.DHParameters{
			Prime:     chat.PeerDH.Prime,
			Generator: chat.PeerDH.Generator,
			PublicKey: chat.PeerDH.PublicKey,
		}
	}

	return chatInfo
}

func (s *ChatService) SubscribeToChatUpdates(empty *emptypb.Empty, stream pb.ChatService_SubscribeToChatUpdatesServer) error {
	ctx := stream.Context()
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return err
	}

	log.Printf("SubscribeToChatUpdates stream started for user: %s", authContext.Username)

	curChats, err := s.getcurActiveChats(ctx, authContext.Username)
	if err != nil {
		return err
	}

	for _, chat := range curChats {
		chatInfo := s.convertChatToChatInfo(chat)
		if err := stream.Send(&pb.ChatUpdate{
			Type: "active",
			Chat: chatInfo,
		}); err != nil {
			return err
		}
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	prevChats := curChats

	for {
		select {
		case <-ticker.C:
			curChats, err := s.getcurActiveChats(ctx, authContext.Username)
			if err != nil {
				log.Printf("Ошибка получения обновлений чата для %s: %v", authContext.Username, err)
				continue
			}

			for id, chat := range curChats {
				if _, exists := prevChats[id]; !exists {
					if err := stream.Send(&pb.ChatUpdate{
						Type: "created",
						Chat: s.convertChatToChatInfo(chat),
					}); err != nil {
						return err
					}
				}
			}

			for id := range prevChats {
				if _, exists := curChats[id]; !exists {
					if err := stream.Send(&pb.ChatUpdate{
						Type: "closed",
						Chat: &pb.ChatInfo{ChatId: id},
					}); err != nil {
						return err
					}
				}
			}

			prevChats = curChats

		case <-ctx.Done():
			log.Printf("SubscribeToChatUpdates окончен: %s, причина: %v", authContext.Username, ctx.Err())
			return ctx.Err()
		}
	}
}
