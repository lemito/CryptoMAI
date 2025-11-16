package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	_ "github.com/jackc/pgx/v5"
	pb "github.com/lemito/CryptoMAI/proto"
)

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserSession struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SessionToken string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	IsActive     bool
}

type AuthContext struct {
	UserID       string
	Username     string
	SessionToken string
}

type authContextKey struct{}

type authService struct {
	pb.UnimplementedAuthServiceServer
	db *sql.DB
}

func NewAuthService(db *sql.DB) *authService {
	return &authService{
		db: db,
	}
}

func initDB(cfg DatabaseConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	log.Println("Successfully connected to database")
	return db, nil
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
		Message: "Регистрация успешна",
	}, nil
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *authService) startSessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, _ := s.db.ExecContext(ctx,
			"DELETE FROM user_sessions WHERE expires_at < NOW() OR is_active = false")
		cancel()
		cnt, err := result.RowsAffected()
		if err != nil {
			log.Fatalf("err %v", err)
		}
		log.Printf("Cleaned %d expired sessions", cnt)
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

const (
	SessionTokenHeader = "x-session-token"
)

type AuthContextKey struct{}

func AuthMiddleware(authService *authService) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		publicMethods := map[string]bool{
			"/proto.AuthService/Register":      true,
			"/proto.AuthService/Login":         true,
			"/proto.AuthService/ValidateToken": true,
		}

		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		if info.FullMethod == "/proto.AuthService/Logout" {
			if logoutReq, ok := req.(*pb.LogoutRequest); ok {
				if logoutReq.SessionToken == "" {
					return nil, status.Error(codes.Unauthenticated, "Токен сессии не предоставлен")
				}
				return handler(ctx, req)
			}
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "Метаданные не предоставлены")
		}

		tokens := md.Get(SessionTokenHeader)
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "Токен сессии не предоставлен")
		}

		sessionToken := tokens[0]
		if sessionToken == "" {
			return nil, status.Error(codes.Unauthenticated, "Токен сессии пуст")
		}

		user, err := authService.ValidateSession(ctx, sessionToken)
		if err != nil {
			return nil, err
		}

		authContext := &AuthContext{
			UserID:       user.ID.String(),
			Username:     user.Username,
			SessionToken: sessionToken,
		}

		ctx = context.WithValue(ctx, authContextKey{}, authContext)
		return handler(ctx, req)
	}
}

func GetAuthContext(ctx context.Context) (*AuthContext, error) {
	authContext, ok := ctx.Value(authContextKey{}).(*AuthContext)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Контекст аутентификации не найден")
	}
	return authContext, nil
}

func main() {
	fmt.Println("Starting Auth Service...")

	dbConfig := DatabaseConfig{
		Host:     "localhost",
		Port:     "5432",
		User:     "meow",
		Password: "meow",
		DBName:   "cryptomai_db",
		SSLMode:  "disable",
	}

	db, err := initDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	authService := NewAuthService(db)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(AuthMiddleware(authService)),
	)

	pb.RegisterAuthServiceServer(server, authService)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Auth Service running on port 50051")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
