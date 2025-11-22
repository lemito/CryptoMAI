package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/lemito/CryptoMAI/proto"
)

type contactsService struct {
	pb.UnimplementedContactServiceServer
	db      *sql.DB
	streams map[string][]pb.ContactService_SubscribeToContactUpdatesServer
	mu      sync.RWMutex
}

func NewContactsService(db *sql.DB) *contactsService {
	return &contactsService{
		db:      db,
		streams: make(map[string][]pb.ContactService_SubscribeToContactUpdatesServer),
	}
}

func (s *contactsService) getCurrentUser(ctx context.Context) (string, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return "", err
	}
	return authContext.Username, nil
}

func (s *contactsService) broadcastToUser(userID string, update *pb.ContactUpdate) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	streams, exists := s.streams[userID]
	if !exists {
		return
	}

	for i, stream := range streams {
		if err := stream.Send(update); err != nil {
			log.Printf("Failed to send update to user %s: %v", userID, err)
			streams[i] = nil
		}
	}
}

func (s *contactsService) AddContact(ctx context.Context, req *pb.ContactRequest) (*pb.CommonResponse, error) {
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return nil, err
	}

	targetUsername := req.GetTargetUsername()
	if targetUsername == "" {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пустое поле",
		}, nil
	}

	if currentUser == targetUsername {
		return &pb.CommonResponse{
			Success: false,
			Message: "Нельзя добавить самого себя",
		}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var targetUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", targetUsername).Scan(&targetUserID)
	if err == sql.ErrNoRows {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пользователь не найден",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось найти пользователя: %v", err)
	}

	var currentUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось получить текущего пользователя: %v", err)
	}

	var existingStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT status FROM contacts 
		WHERE user_id = $1 AND contact_id = $2`,
		currentUserID, targetUserID).Scan(&existingStatus)

	switch err {
	case nil:
		switch existingStatus {
		case "pending":
			return &pb.CommonResponse{
				Success: false,
				Message: "Запрос на добавление уже отправлен",
			}, nil
		case "accepted":
			return &pb.CommonResponse{
				Success: false,
				Message: "Контакт уже существует",
			}, nil
		case "rejected":
			_, err = tx.ExecContext(ctx, `
				UPDATE contacts SET status = 'pending', created_at = NOW() 
				WHERE user_id = $1 AND contact_id = $2`,
				currentUserID, targetUserID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "не удалось обновить контакт: %v", err)
			}
		}
	case sql.ErrNoRows:
		_, err = tx.ExecContext(ctx, `
			INSERT INTO contacts (user_id, contact_id, status) 
			VALUES ($1, $2, 'pending')
			ON CONFLICT (user_id, contact_id) DO NOTHING`,
			currentUserID, targetUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось создать запрос на добавление контакта: %v", err)
		}
	default:
		return nil, status.Errorf(codes.Internal, "не удалось проверить существующий контакт: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось зафиксировать транзакцию: %v", err)
	}

	s.broadcastToUser(targetUserID, &pb.ContactUpdate{
		Type: "new_request",
		Contact: &pb.ContactInfo{
			Username:  currentUser,
			Status:    "pending",
			RequestId: currentUserID,
		},
	})
	
	return &pb.CommonResponse{
		Success: true,
		Message: "Запрос на добавление в контакты отправлен успешно",
	}, nil
}

func (s *contactsService) HandleContactRequest(ctx context.Context, req *pb.ContactActionRequest) (*pb.CommonResponse, error) {
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return nil, err
	}

	requestID := req.GetRequestId()
	approve := req.GetApprove()

	if requestID == "" {
		return &pb.CommonResponse{
			Success: false,
			Message: "ID запроса обязателен",
		}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var currentUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось получить текущего пользователя: %v", err)
	}

	var fromUserID string
	var currentStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT user_id, status FROM contacts 
		WHERE user_id = $1 AND contact_id = $2 AND status = 'pending'`,
		requestID, currentUserID).Scan(&fromUserID, &currentStatus)

	if err == sql.ErrNoRows {
		return &pb.CommonResponse{
			Success: false,
			Message: "Запрос на добавление не найден или уже обработан",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось найти запрос на добавление контакта: %v", err)
	}

	if approve {
		_, err = tx.ExecContext(ctx, `
			UPDATE contacts SET status = 'accepted' 
			WHERE user_id = $1 AND contact_id = $2`,
			fromUserID, currentUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось принять контакт: %v", err)
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO contacts (user_id, contact_id, status) 
			VALUES ($1, $2, 'accepted')
			ON CONFLICT (user_id, contact_id) DO UPDATE SET status = 'accepted'`,
			currentUserID, fromUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось создать обратный контакт: %v", err)
		}
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE contacts SET status = 'rejected' 
			WHERE user_id = $1 AND contact_id = $2`,
			fromUserID, currentUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "не удалось отклонить контакт: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось зафиксировать транзакцию: %v", err)
	}

	action := "принят"
	if !approve {
		action = "отклонен"
	}

	return &pb.CommonResponse{
		Success: true,
		Message: fmt.Sprintf("Запрос на добавление в контакты %s", action),
	}, nil
}

func (s *contactsService) GetContacts(empty *emptypb.Empty, stream pb.ContactService_GetContactsServer) error {
	ctx := stream.Context()
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return err
	}

	var currentUserID string
	err = s.db.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "не удалось получить текущего пользователя: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, c.status, c.created_at 
		FROM contacts c
		JOIN users u ON c.contact_id = u.id
		WHERE c.user_id = $1 AND c.status = 'accepted'
		ORDER BY u.username`,
		currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "не удалось получить контакты: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username, contactStatus string
		var createdAt time.Time
		if err := rows.Scan(&username, &contactStatus, &createdAt); err != nil {
			return status.Errorf(codes.Internal, "не удалось сканировать контакты: %v", err)
		}

		if err := stream.Send(&pb.ContactInfo{
			Username: username,
			Status:   "active",
		}); err != nil {
			return err
		}
	}

	pendingRows, err := s.db.QueryContext(ctx, `
        SELECT u.id, u.username, c.created_at 
        FROM contacts c
        JOIN users u ON c.user_id = u.id
        WHERE c.contact_id = $1 AND c.status = 'pending'
        ORDER BY c.created_at`,
		currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "не удалось получить ожидающие запросы: %v", err)
	}
	defer pendingRows.Close()

	for pendingRows.Next() {
		var userID string
		var username string
		var createdAt time.Time
		if err := pendingRows.Scan(&userID, &username, &createdAt); err != nil {
			return status.Errorf(codes.Internal, "не удалось сканировать ожидающий контакт: %v", err)
		}

		if err := stream.Send(&pb.ContactInfo{
			Username:  username,
			Status:    "pending",
			RequestId: userID,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *contactsService) SubscribeToContactUpdates(empty *emptypb.Empty, stream pb.ContactService_SubscribeToContactUpdatesServer) error {
	ctx := stream.Context()
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return err
	}

	var currentUserID string
	err = s.db.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "не удалось получить текущего пользователя: %v", err)
	}

	s.mu.Lock()
	s.streams[currentUserID] = append(s.streams[currentUserID], stream)
	streamIndex := len(s.streams[currentUserID]) - 1
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		if streams, exists := s.streams[currentUserID]; exists {
			if streamIndex < len(streams) {
				streams[streamIndex] = streams[len(streams)-1]
				s.streams[currentUserID] = streams[:len(streams)-1]
			}

			if len(s.streams[currentUserID]) == 0 {
				delete(s.streams, currentUserID)
			}
		}
	}()

	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, c.status
		FROM contacts c
		JOIN users u ON c.contact_id = u.id
		WHERE c.user_id = $1
		ORDER BY u.username`,
		currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "не удалось получить контакты для обновлений: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username, contactStatus string
		if err := rows.Scan(&username, &contactStatus); err != nil {
			return status.Errorf(codes.Internal, "не удалось сканировать контакт для обновлений: %v", err)
		}

		if err := stream.Send(&pb.ContactUpdate{
			Type: "initial",
			Contact: &pb.ContactInfo{
				Username: username,
				Status:   contactStatus,
			},
		}); err != nil {
			return err
		}
	}

	<-ctx.Done()
	return ctx.Err()
}

func (s *contactsService) RemoveContact(ctx context.Context, req *pb.RemoveContactRequest) (*pb.CommonResponse, error) {
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return nil, err
	}

	contactUsername := req.GetContactUsername()
	if contactUsername == "" {
		return &pb.CommonResponse{
			Success: false,
			Message: "Имя контакта обязательно",
		}, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось начать транзакцию: %v", err)
	}
	defer tx.Rollback()

	var currentUserID, contactUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось получить текущего пользователя: %v", err)
	}

	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", contactUsername).Scan(&contactUserID)
	if err == sql.ErrNoRows {
		return &pb.CommonResponse{
			Success: false,
			Message: "Контакт не найден",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось получить пользователя контакта: %v", err)
	}

	result, err := tx.ExecContext(ctx, `
		DELETE FROM contacts 
		WHERE (user_id = $1 AND contact_id = $2) 
		   OR (user_id = $2 AND contact_id = $1)`,
		currentUserID, contactUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось удалить контакт: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось получить количество затронутых строк: %v", err)
	}

	if rowsAffected == 0 {
		return &pb.CommonResponse{
			Success: false,
			Message: "Контакт не найден",
		}, nil
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "не удалось зафиксировать транзакцию: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Контакт успешно удален",
	}, nil
}
