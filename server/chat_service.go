package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/lemito/CryptoMAI/proto"
)

type ChatService struct {
	pb.UnimplementedChatServiceServer
	db *sql.DB

	waiting map[string]chan struct{}
	broker  *DHExchangeBroker

	logger       *zap.SugaredLogger
}

type pendingDH struct {
	firstReq     *pb.DHParametersExchange                   
	secondReq    *pb.DHParametersExchange                        
	firstStream  pb.ChatService_ExchangeDHParametersStreamServer
	secondStream pb.ChatService_ExchangeDHParametersStreamServer 
	mu           sync.RWMutex
	isCompleted  bool
}

type DHExchangeBroker struct {
	mu      sync.RWMutex
	pending map[string]*pendingDH
	timeout time.Duration
	logger  *zap.SugaredLogger
}

func NewDHExchangeBroker(timeout time.Duration, logger *zap.SugaredLogger) *DHExchangeBroker {
	return &DHExchangeBroker{
		pending: make(map[string]*pendingDH),
		timeout: timeout,
		logger:  logger,
	}
}

func NewChatService(log *zap.SugaredLogger, db *sql.DB) *ChatService {
	// logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	broker := NewDHExchangeBroker(10*time.Minute, log)

	return &ChatService{
		db:      db,
		waiting: make(map[string]chan struct{}),
		logger:  log,
		broker:  broker,
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

	_, err = tx.ExecContext(ctx, `
            INSERT INTO user_chats (user_id, chat_id, username, is_active, joined_at)
            SELECT u.id, $1, u.username, true, $2
            FROM users u WHERE u.username = $3`,
		chatID, now, initiatorUsername)
	if err != nil {
		return nil, fmt.Errorf("не удалось добавить пользователя %s в чат: %v", initiatorUsername, err)
	}
	_, err = tx.ExecContext(ctx, `
            INSERT INTO user_chats (user_id, chat_id, username, is_active, joined_at)
            SELECT u.id, $1, u.username, false, $2
            FROM users u WHERE u.username = $3`,
		chatID, now, req.ContactUsername)
	if err != nil {
		return nil, fmt.Errorf("не удалось добавить пользователя %s в чат: %v", req.ContactUsername, err)
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
			s.logger.Infof("Ошибка очистки чатов: %v", err)
		}
		s.logger.Infof("Очищено %d неактивных чатов", cnt)
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

	s.logger.Infof("GetActiveChats stream started for user: %s", authContext.Username)

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
	s.logger.Infof("Поток завершен для: %s", authContext.Username)
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
			s.logger.Infof("ошибка: %v", err)
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

	s.logger.Infof("SubscribeToChatUpdates stream started for user: %s", authContext.Username)

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
				s.logger.Infof("Ошибка получения обновлений чата для %s: %v", authContext.Username, err)
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
			s.logger.Infof("SubscribeToChatUpdates окончен: %s, причина: %v", authContext.Username, ctx.Err())
			return ctx.Err()
		}
	}
}

func (s *ChatService) ExchangeDHParametersStream(stream pb.ChatService_ExchangeDHParametersStreamServer) error {
	ctx := stream.Context()

	authContext, err := GetAuthContext(ctx)
	if err != nil {
		s.logger.Error("Отсутствует authContext", "error", err)
		return status.Error(codes.Unauthenticated, "No authContext")
	}

	username := authContext.Username

	req, err := stream.Recv()
	if err == io.EOF {
		s.logger.Debug("EOF")
		return nil
	}
	if err != nil {
		s.logger.Error("Ошибка при получении данных из потока", "error", err)
		return status.Error(codes.Internal, "Failed to receive request")
	}

	chatId := req.GetChatId()
	if chatId == "" {
		return status.Error(codes.InvalidArgument, "chat_id is required")
	}

	chat, err := s.getChatInfo(ctx, chatId)
	if err != nil {
		s.logger.Error("Чат не найден", "chat_id", chatId, "username", username, "error", err)
		return status.Error(codes.NotFound, "Chat not found")
	}

	if chat.Initiator != username && chat.Participant != username {
		s.logger.Warn("Пользователь не принадлежит к комнате", "chat_id", chatId, "username", username)
		return status.Error(codes.Unauthenticated, "Not belongs to room")
	}

	s.logger.Debug("Начало обмена параметрами Диффи-Хеллмана", "chat_id", chatId, "username", username)

	exchangeCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var peerExchange *pendingDH

	s.broker.mu.Lock()

	if existing, ok := s.broker.pending[chatId]; ok {
		peerExchange = existing
		peerExchange.mu.Lock()
		peerExchange.secondReq = req
		peerExchange.secondStream = stream
		peerExchange.isCompleted = false
		peerExchange.mu.Unlock()
		s.broker.mu.Unlock()

		s.logger.Info("Подключился второй участник", "chat_id", chatId, "username", username)

		return s.performDHExchange(exchangeCtx, chatId, username, peerExchange, true)
	} else {
		peerExchange = &pendingDH{
			firstReq:    req,
			firstStream: stream,
			isCompleted: false,
		}
		s.broker.pending[chatId] = peerExchange
		s.broker.mu.Unlock()

		s.logger.Info("Первый участник ожидает", "chat_id", chatId, "username", username)

		return s.waitForSecondPeer(exchangeCtx, chatId, username, peerExchange)
	}
}

func (s *ChatService) waitForSecondPeer(ctx context.Context, chatId, username string, exchange *pendingDH) error {
	defer func() {
		s.broker.mu.Lock()
		delete(s.broker.pending, chatId)
		s.broker.mu.Unlock()

		exchange.mu.Lock()
		exchange.isCompleted = true
		exchange.mu.Unlock()

		s.logger.Debug("Очистка ожидающего обмена", "chat_id", chatId)
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			exchange.mu.RLock()
			hasSecond := exchange.secondReq != nil && exchange.secondStream != nil
			exchange.mu.RUnlock()

			if hasSecond {
				s.logger.Info("Второй участник прибыл, начинаем обмен", "chat_id", chatId)
				return s.performDHExchange(ctx, chatId, username, exchange, false)
			}

		case <-ctx.Done():
			s.logger.Info("Истекло время ожидания второго участника", "chat_id", chatId, "error", ctx.Err())
			return status.Error(codes.DeadlineExceeded, "Timeout waiting for second peer")
		}
	}
}

func (s *ChatService) performDHExchange(ctx context.Context, chatId, username string, exchange *pendingDH, isSecondPeer bool) error {
	exchange.mu.Lock()
	defer exchange.mu.Unlock()

	if exchange.isCompleted {
		s.logger.Warn("Обмен уже завершён", "chat_id", chatId)
		return nil
		// return status.Error(codes.AlreadyExists, "Exchange already completed")
	}

	if exchange.firstReq == nil || exchange.secondReq == nil {
		s.logger.Error("Отсутствуют запросы", "chat_id", chatId,
			"first_req", exchange.firstReq != nil,
			"second_req", exchange.secondReq != nil)
		return status.Error(codes.Internal, "Missing DH parameters")
	}

	s.logger.Info("Обмен параметрами Диффи-Хеллмана", "chat_id", chatId,
		"is_second_peer", isSecondPeer, "username", username)

	var streamToUse pb.ChatService_ExchangeDHParametersStreamServer
	var paramsToSend *pb.DHParameters

	if isSecondPeer {
		streamToUse = exchange.secondStream
		if exchange.firstReq.GetParameters() == nil {
			s.logger.Error("Параметры первого участника отсутствуют (nil)", "chat_id", chatId)
			return status.Error(codes.Internal, "First peer DH parameters missing")
		}
		paramsToSend = exchange.firstReq.GetParameters()

		if err := streamToUse.Send(&pb.DHParametersResponse{
			Response: &pb.DHParametersResponse_PeerParams{
				PeerParams: paramsToSend,
			},
		}); err != nil {
			s.logger.Error("Не удалось отправить параметры второму участнику", "chat_id", chatId, "error", err)
			return status.Error(codes.Internal, "Failed to send DH parameters")
		}

		s.logger.Debug("Параметры первого участника отправлены второму", "chat_id", chatId)

		if exchange.firstStream != nil && exchange.secondReq.GetParameters() != nil {
			if err := exchange.firstStream.Send(&pb.DHParametersResponse{
				Response: &pb.DHParametersResponse_PeerParams{
					PeerParams: exchange.secondReq.GetParameters(),
				},
			}); err != nil {
				s.logger.Error("Не удалось отправить параметры первому участнику", "chat_id", chatId, "error", err)
			} else {
				s.logger.Debug("Параметры второго участника отправлены первому", "chat_id", chatId)
			}
		}
	} else {
		streamToUse = exchange.firstStream
		if exchange.secondReq.GetParameters() == nil {
			s.logger.Error("Параметры второго участника отсутствуют (nil)", "chat_id", chatId)
			return status.Error(codes.Internal, "Second peer DH parameters missing")
		}
		paramsToSend = exchange.secondReq.GetParameters()

		if err := streamToUse.Send(&pb.DHParametersResponse{
			Response: &pb.DHParametersResponse_PeerParams{
				PeerParams: paramsToSend,
			},
		}); err != nil {
			s.logger.Error("Не удалось отправить параметры первому участнику", "chat_id", chatId, "error", err)
			return status.Error(codes.Internal, "Failed to send DH parameters")
		}

		s.logger.Debug("Параметры второго участника отправлены первому", "chat_id", chatId)
	}

	exchange.isCompleted = true
	s.logger.Info("Обмен параметрами Диффи-Хеллмана успешно завершён", "chat_id", chatId, "username", username)

	return nil
}

func (s *ChatService) cleanupOldExchanges() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.broker.mu.Lock()
		for chatId, exchange := range s.broker.pending {
			exchange.mu.RLock()
			isOld := exchange.isCompleted || time.Since(time.Now()) > 5*time.Minute
			exchange.mu.RUnlock()

			if isOld {
				delete(s.broker.pending, chatId)
				s.logger.Debug("Очистка устаревшего обмена", "chat_id", chatId)
			}
		}
		s.broker.mu.Unlock()
	}
}

func (s *ChatService) Start() {
	go s.cleanupOldExchanges()
}

func (s *ChatService) GetChatDHParams(ctx context.Context, req *pb.GetChatDHParamsRequest) (*pb.GetChatDHParamsResponse, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChatId == "" {
		return nil, status.Error(codes.InvalidArgument, "chat_id пуст")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Error(codes.Internal, "ошибка транзакции")
	}
	defer tx.Rollback()

	var exists bool
	err = tx.QueryRowContext(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM user_chats 
            WHERE chat_id = $1 AND username = $2
        )`, req.ChatId, authContext.Username).Scan(&exists)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "ошибка проверки: %v", err)
	}
	if !exists {
		return nil, status.Error(codes.PermissionDenied, "доступ запрещен")
	}

	var (
		initiatorDHJSON []byte
		peerDHJSON      []byte
	)
	err = tx.QueryRowContext(ctx, `
        SELECT initiator_dh_params, 
               peer_dh_params
        FROM chats 
        WHERE id = $1 AND is_active = true`,
		req.ChatId).Scan(&initiatorDHJSON, &peerDHJSON)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "активный чат не найден")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "ошибка запроса: %v", err)
	}

	var initiatorDH DHParams
	if err := json.Unmarshal(initiatorDHJSON, &initiatorDH); err != nil {
		return nil, status.Errorf(codes.Internal, "ошибка парсинга initiator_dh_params: %v", err)
	}

	// var peerDH DHParams
	// if err := json.Unmarshal(peerDHJSON, &peerDH); err != nil {
	// 	return nil, status.Errorf(codes.Internal, "ошибка парсинга peerDH_dh_params: %v", err)
	// }

	response := &pb.GetChatDHParamsResponse{
		Success: true,
		InitiatorParams: &pb.DHParameters{
			Prime:     initiatorDH.Prime,
			Generator: initiatorDH.Generator,
			PublicKey: initiatorDH.PublicKey,
		},
		PeerPublicKey: []byte(""),
	}

	return response, nil
}

func (s *ChatService) getChatInfo(ctx context.Context, chatID string) (*Chat, error) {
	var chat Chat
	var initiatorDHJSON, peerDHJSON []byte
	var algorithmStr, modeStr, paddingStr string

	err := s.db.QueryRowContext(ctx, `
		SELECT id, initiator_username, participant_username, 
			   algorithm, mode, padding, base_iv,
			   initiator_dh_params, peer_dh_params, is_active, created_at
		FROM chats 
		WHERE id = $1 AND is_active = true`,
		chatID).Scan(
		&chat.ID, &chat.Initiator, &chat.Participant,
		&algorithmStr, &modeStr, &paddingStr, &chat.BaseIV,
		&initiatorDHJSON, &peerDHJSON, &chat.IsActive, &chat.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("chat not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
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
