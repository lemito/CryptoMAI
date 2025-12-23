package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/lemito/CryptoMAI/proto"
)

type authService struct {
	pb.UnimplementedAuthServiceServer
	db     *sql.DB
	logger *zap.SugaredLogger
}

func NewAuthService(log *zap.SugaredLogger, db *sql.DB) *authService {
	return &authService{
		db:     db,
		logger: log,
	}
}

func (s *authService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.CommonResponse, error) {
	if req.Username == "" || req.Password == "" {
		return &pb.CommonResponse{
			Success: false,
			Message: "Логин и пароль не могут быть пустыми",
		}, nil
	}

	if len(req.Username) < 3 || len(req.Username) > 50 {
		return &pb.CommonResponse{
			Success: false,
			Message: "Логин должен быть от 3 до 50 символов",
		}, nil
	}

	if len(req.Password) < 6 {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пароль должен содержать минимум 6 символов",
		}, nil
	}

	var exists bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
		req.Username).Scan(&exists)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка проверки пользователя: %v", err)
	}

	if exists {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пользователь с таким именем уже существует",
		}, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка в bcrypt-hash: %v", err)
	}

	userID := uuid.New()
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)",
		userID, req.Username, string(hash))

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка создания пользователя: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: fmt.Sprintf("[%s] Регистрация успешна", userID.String()),
	}, nil
}

func (s *authService) startSessionCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result, err := s.db.ExecContext(cleanupCtx,
				"DELETE FROM user_sessions WHERE expires_at < NOW() OR is_active = false")
			cancel()

			if err != nil {
				s.logger.Errorf("Error cleaning sessions: %v", err)
				continue
			}

			cnt, err := result.RowsAffected()
			if err != nil {
				s.logger.Errorf("Error getting rows affected: %v", err)
				continue
			}

			if cnt > 0 {
				s.logger.Infof("Cleaned %d expired sessions", cnt)
			}

		case <-ctx.Done():
			s.logger.Info("Session cleanup stopped")
			return
		}
	}
}

func (s *authService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	if req.Username == "" || req.Password == "" {
		return &pb.AuthResponse{
			Success: false,
			Message: "Логин и пароль не могут быть пустыми",
		}, nil
	}

	var user User
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash FROM users WHERE username = $1",
		req.Username).Scan(&user.ID, &user.Username, &user.PasswordHash)

	if err == sql.ErrNoRows {
		return &pb.AuthResponse{
			Success: false,
			Message: "Пользователь не найден",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка поиска пользователя: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return &pb.AuthResponse{
			Success: false,
			Message: "Неверный пароль",
		}, nil
	}

	// var existingSessionID string
	// err = s.db.QueryRowContext(ctx,
	// 	"SELECT id FROM user_sessions WHERE user_id = $1 AND is_active = true AND expires_at > NOW()",
	// 	user.ID).Scan(&existingSessionID)

	// if err == nil {
	// 	return &pb.AuthResponse{
	// 		Success: false,
	// 		Message: "Пользователь уже авторизован. Завершите текущую сессию перед входом или дождитесь её окончания",
	// 	}, nil
	// } else if err != sql.ErrNoRows {
	// 	return nil, status.Errorf(codes.Internal, "Ошибка проверки сессии: %v", err)
	// }

	token, err := generateSecureToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка генерации токена: %v", err)
	}

	sessionID := uuid.New()
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO user_sessions (id, user_id, session_token, expires_at) VALUES ($1, $2, $3, $4)",
		sessionID, user.ID, token, expiresAt)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка создания сессии: %v", err)
	}

	return &pb.AuthResponse{
		Success:      true,
		SessionToken: token,
		Message:      "Авторизация успешна",
	}, nil
}

func (s *authService) ValidateSession(ctx context.Context, sessionToken string) (*User, error) {
	var session UserSession
	var user User

	err := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, s.session_token, s.expires_at, s.is_active,
			u.id, u.username, u.password_hash
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_token = $1 AND s.is_active = true`,
		sessionToken).Scan(
		&session.ID, &session.UserID, &session.SessionToken, &session.ExpiresAt, &session.IsActive,
		&user.ID, &user.Username, &user.PasswordHash)

	if err == sql.ErrNoRows {
		return nil, status.Error(codes.Unauthenticated, "Недействительная сессия")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка проверки сессии: %v", err)
	}

	if time.Now().After(session.ExpiresAt) {
		s.db.ExecContext(ctx, "UPDATE user_sessions SET is_active = false WHERE id = $1", session.ID)
		return nil, status.Error(codes.Unauthenticated, "Сессия истекла")
	}

	return &user, nil
}

func (s *authService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.CommonResponse, error) {
	s.logger.Info("Выход для ", "SessionToken: ", req.SessionToken)
	result, err := s.db.ExecContext(ctx,
		"UPDATE user_sessions SET is_active = false WHERE session_token = $1",
		req.SessionToken)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка выхода из системы: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return &pb.CommonResponse{
			Success: false,
			Message: "Сессия не найдена",
		}, nil
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Выход выполнен успешно",
	}, nil
}

func (s *authService) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	user, err := s.ValidateSession(ctx, req.SessionToken)
	if err != nil {
		return &pb.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:    true,
		UserId:   user.ID.String(),
		Username: user.Username,
	}, nil
}
