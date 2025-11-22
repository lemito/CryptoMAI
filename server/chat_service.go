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

	// Убираем проверку на существующий чат - разрешаем multiple chats
	newChat, err := s.createNewChatInDB(ctx, authContext.Username, req)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create chat: "+err.Error())
	}

	return s.convertChatToChatInfo(newChat), nil
}

func (s *ChatService) validateCreateChatRequest(req *pb.CreateChatRequest) error {
	if req.ContactUsername == "" {
		return fmt.Errorf("contact username is required")
	}
	if req.EncryptionParams == nil {
		return fmt.Errorf("encryption parameters are required")
	}
	if len(req.EncryptionParams.ChatIv) == 0 {
		return fmt.Errorf("chat IV is required")
	}
	if req.InitiatorParams == nil {
		return fmt.Errorf("DH parameters are required")
	}
	if req.InitiatorParams.Prime == nil || req.InitiatorParams.Generator == nil || req.InitiatorParams.PublicKey == nil {
		return fmt.Errorf("DH parameters are incomplete")
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
		return status.Errorf(codes.Internal, "failed to validate contact: %v", err)
	}
	if !exists {
		return status.Error(codes.NotFound, "contact not found or not accepted")
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
		return nil, fmt.Errorf("failed to marshal DH params: %v", err)
	}

	chatID := uuid.New().String()
	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %v", err)
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
		return nil, fmt.Errorf("failed to insert chat: %v", err)
	}

	users := []string{initiatorUsername, req.ContactUsername}
	for _, username := range users {
		_, err = tx.ExecContext(ctx, `
            INSERT INTO user_chats (user_id, chat_id, username, is_active, joined_at)
            SELECT u.id, $1, u.username, true, $2
            FROM users u WHERE u.username = $3`,
			chatID, now, username)
		if err != nil {
			return nil, fmt.Errorf("failed to add user %s to chat: %v", username, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
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
		return nil, status.Error(codes.InvalidArgument, "chat ID is required")
	}
	if req.PeerParams == nil {
		return nil, status.Error(codes.InvalidArgument, "DH parameters are required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Проверяем, что пользователь является участником чата
	var participantUsername string
	err = tx.QueryRowContext(ctx, `
		SELECT participant_username FROM chats 
		WHERE id = $1 AND is_active = true`,
		req.ChatId).Scan(&participantUsername)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "active chat not found")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find chat: %v", err)
	}

	if participantUsername != authContext.Username {
		return nil, status.Error(codes.PermissionDenied, "you are not the participant of this chat")
	}

	peerDH := DHParams{
		Prime:     req.PeerParams.Prime,
		Generator: req.PeerParams.Generator,
		PublicKey: req.PeerParams.PublicKey,
	}
	peerDHJSON, err := json.Marshal(peerDH)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal DH params: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE chats SET peer_dh_params = $1 
		WHERE id = $2`,
		peerDHJSON, req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update chat: %v", err)
	}

	// Обновляем запись в user_chats для участника
	_, err = tx.ExecContext(ctx, `
		UPDATE user_chats SET is_active = true, joined_at = $1 
		WHERE chat_id = $2 AND username = $3`,
		time.Now(), req.ChatId, authContext.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user chat: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit transaction: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Successfully joined the chat",
	}, nil
}

func (s *ChatService) CloseChat(ctx context.Context, req *pb.CloseChatRequest) (*pb.CommonResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "chat ID is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	var initiatorUsername string
	err = tx.QueryRowContext(ctx, `
		SELECT initiator_username FROM chats 
		WHERE id = $1 AND is_active = true`,
		req.ChatId).Scan(&initiatorUsername)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "active chat not found")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find chat: %v", err)
	}

	if initiatorUsername != authContext.Username {
		return nil, status.Error(codes.PermissionDenied, "only chat initiator can close the chat")
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE chats SET is_active = false 
		WHERE id = $1`,
		req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to close chat: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE user_chats SET is_active = false, left_at = $1 
		WHERE chat_id = $2`,
		time.Now(), req.ChatId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user chats: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit transaction: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Chat closed successfully",
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
			log.Printf("Error cleaning chat: %v", err)
		}
		log.Printf("Cleaned %d expired chat", cnt)
	}
}

func (s *ChatService) LeaveChat(ctx context.Context, req *pb.CloseChatRequest) (*pb.CommonResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "chat ID is required")
	}

	var userChat UserChat
	err = s.db.QueryRowContext(ctx, `
		SELECT username, is_active 
		FROM user_chats 
		WHERE chat_id = $1 AND username = $2`,
		req.ChatId, authContext.Username).Scan(&userChat.Username, &userChat.IsActive)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "you are not a participant of this chat")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find user chat: %v", err)
	}

	if !userChat.IsActive {
		return &pb.CommonResponse{
			Success: false,
			Message: "You have already left this chat",
		}, nil
	}

	now := time.Now()
	_, err = s.db.ExecContext(ctx, `
		UPDATE user_chats SET is_active = false, left_at = $1 
		WHERE chat_id = $2 AND username = $3`,
		now, req.ChatId, authContext.Username)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to leave chat: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Successfully left the chat",
	}, nil
}

func (s *ChatService) GetActiveChats(empty *emptypb.Empty, stream pb.ChatService_GetActiveChatsServer) error {
	ctx := stream.Context()
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return err
	}

	log.Printf("GetActiveChats stream started for user: %s", authContext.Username)

	// Отправляем все активные чаты пользователя
	chats, err := s.getCurrentActiveChats(ctx, authContext.Username)
	if err != nil {
		return err
	}

	for _, chat := range chats {
		chatInfo := s.convertChatToChatInfo(chat)
		if err := stream.Send(chatInfo); err != nil {
			return err
		}
	}

	// Ждем завершения контекста
	<-ctx.Done()
	log.Printf("GetActiveChats stream ended for user: %s", authContext.Username)
	return ctx.Err()
}

func (s *ChatService) getCurrentActiveChats(ctx context.Context, username string) (map[string]*Chat, error) {
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
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		chat, err := s.scanChatFromRow(rows)
		if err != nil {
			log.Printf("Error scanning chat row: %v", err)
			continue
		}
		chats[chat.ID] = chat
	}

	if err = rows.Err(); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("failed to unmarshal initiator DH params: %v", err)
	}

	if len(peerDHJSON) > 0 {
		var peerDH DHParams
		if err := json.Unmarshal(peerDHJSON, &peerDH); err != nil {
			return nil, fmt.Errorf("failed to unmarshal peer DH params: %v", err)
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

	currentChats, err := s.getCurrentActiveChats(ctx, authContext.Username)
	if err != nil {
		return err
	}

	for _, chat := range currentChats {
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

	previousChats := currentChats

	for {
		select {
		case <-ticker.C:
			currentChats, err := s.getCurrentActiveChats(ctx, authContext.Username)
			if err != nil {
				log.Printf("Error getting chat updates for %s: %v", authContext.Username, err)
				continue
			}

			for id, chat := range currentChats {
				if _, exists := previousChats[id]; !exists {
					if err := stream.Send(&pb.ChatUpdate{
						Type: "created",
						Chat: s.convertChatToChatInfo(chat),
					}); err != nil {
						return err
					}
				}
			}

			for id := range previousChats {
				if _, exists := currentChats[id]; !exists {
					if err := stream.Send(&pb.ChatUpdate{
						Type: "closed",
						Chat: &pb.ChatInfo{ChatId: id},
					}); err != nil {
						return err
					}
				}
			}

			previousChats = currentChats

		case <-ctx.Done():
			log.Printf("SubscribeToChatUpdates stream ended for user: %s, reason: %v", authContext.Username, ctx.Err())
			return ctx.Err()
		}
	}
}
