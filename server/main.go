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
	"google.golang.org/protobuf/types/known/emptypb"

	_ "github.com/jackc/pgx/v5/stdlib"
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

type contactsService struct {
	pb.UnimplementedContactServiceServer
	db *sql.DB
}

func NewAuthService(db *sql.DB) *authService {
	return &authService{
		db: db,
	}
}

func NewContactsService(db *sql.DB) *contactsService {
	return &contactsService{
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
		Message: fmt.Sprintf("[%s] Регистрация успешна", userID.String()),
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
			log.Printf("Error cleaning sessions: %v", err)
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
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		publicMethods := map[string]bool{
			"/chat.AuthService/Register":      true,
			"/chat.AuthService/Login":         true,
			"/chat.AuthService/ValidateToken": true,
		}

		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		if info.FullMethod == "/chat.AuthService/Logout" {
			if logoutReq, ok := req.(*pb.LogoutRequest); ok {
				if logoutReq.SessionToken == "" {
					return nil, status.Error(codes.Unauthenticated, "Токен сессии не предоставлен")
				}
				user, err := authService.ValidateSession(ctx, logoutReq.SessionToken)
				if err != nil {
					return nil, err
				}
				authContext := &AuthContext{
					UserID:       user.ID.String(),
					Username:     user.Username,
					SessionToken: logoutReq.SessionToken,
				}
				ctx = context.WithValue(ctx, AuthContextKey{}, authContext)
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

		ctx = context.WithValue(ctx, AuthContextKey{}, authContext)
		return handler(ctx, req)
	}
}

func GetAuthContext(ctx context.Context) (*AuthContext, error) {
	authContext, ok := ctx.Value(AuthContextKey{}).(*AuthContext)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Контекст аутентификации не найден")
	}
	return authContext, nil
}

func AuthStreamMiddleware(authService *authService) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		publicMethods := map[string]bool{
			// Streaming методы не должны быть публичными, так как требуют аутентификации
		}
		log.Printf("Stream method called: %s", info.FullMethod)

		if publicMethods[info.FullMethod] {
			return handler(srv, stream)
		}

		md, ok := metadata.FromIncomingContext(stream.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "Метаданные не предоставлены")
		}

		tokens := md.Get(SessionTokenHeader)
		if len(tokens) == 0 {
			return status.Error(codes.Unauthenticated, "Токен сессии не предоставлен")
		}

		sessionToken := tokens[0]
		if sessionToken == "" {
			return status.Error(codes.Unauthenticated, "Токен сессии пуст")
		}

		user, err := authService.ValidateSession(stream.Context(), sessionToken)
		if err != nil {
			log.Printf("Auth failed for stream %s: %v", info.FullMethod, err)
			return err
		}

		authContext := &AuthContext{
			UserID:       user.ID.String(),
			Username:     user.Username,
			SessionToken: sessionToken,
		}

		ctx := context.WithValue(stream.Context(), AuthContextKey{}, authContext)

		// Создаем обертку для stream с новым контекстом
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		log.Printf("Auth successful for stream %s, user: %s", info.FullMethod, authContext.Username)

		return handler(srv, wrappedStream)
	}
}

// Обертка для ServerStream с переопределенным контекстом
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

func (s *contactsService) getCurrentUser(ctx context.Context) (string, error) {
	authContext, err := GetAuthContext(ctx)
	if err != nil {
		return "", err
	}
	return authContext.Username, nil
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
		return nil, status.Errorf(codes.Internal, "failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// ID целевого пользователя
	var targetUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", targetUsername).Scan(&targetUserID)
	if err == sql.ErrNoRows {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пользователь не найден",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find user: %v", err)
	}

	// ID текущего пользователя
	var currentUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get current user: %v", err)
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
				return nil, status.Errorf(codes.Internal, "failed to update contact: %v", err)
			}
		}
	case sql.ErrNoRows:
		_, err = tx.ExecContext(ctx, `
			INSERT INTO contacts (user_id, contact_id, status) 
			VALUES ($1, $2, 'pending')
			ON CONFLICT (user_id, contact_id) DO NOTHING`,
			currentUserID, targetUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create contact request: %v", err)
		}
	default:
		return nil, status.Errorf(codes.Internal, "failed to check existing contact: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit transaction: %v", err)
	}

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
		return nil, status.Errorf(codes.Internal, "failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	var currentUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get current user: %v", err)
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
		return nil, status.Errorf(codes.Internal, "failed to find contact request: %v", err)
	}

	if approve {
		_, err = tx.ExecContext(ctx, `
			UPDATE contacts SET status = 'accepted' 
			WHERE user_id = $1 AND contact_id = $2`,
			fromUserID, currentUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to accept contact: %v", err)
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO contacts (user_id, contact_id, status) 
			VALUES ($1, $2, 'accepted')
			ON CONFLICT (user_id, contact_id) DO UPDATE SET status = 'accepted'`,
			currentUserID, fromUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create reverse contact: %v", err)
		}
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE contacts SET status = 'rejected' 
			WHERE user_id = $1 AND contact_id = $2`,
			fromUserID, currentUserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to reject contact: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit transaction: %v", err)
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
		return status.Errorf(codes.Internal, "failed to get current user: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, c.status, c.created_at 
		FROM contacts c
		JOIN users u ON c.contact_id = u.id
		WHERE c.user_id = $1 AND c.status = 'accepted'
		ORDER BY u.username`,
		currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get contacts: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username, contactStatus string
		var createdAt time.Time
		if err := rows.Scan(&username, &contactStatus, &createdAt); err != nil {
			return status.Errorf(codes.Internal, "failed to scan contacts: %v", err)
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
		return status.Errorf(codes.Internal, "failed to get pending requests: %v", err)
	}
	defer pendingRows.Close()

	for pendingRows.Next() {
		var userID string
		var username string
		var createdAt time.Time
		if err := pendingRows.Scan(&userID, &username, &createdAt); err != nil {
			return status.Errorf(codes.Internal, "failed to scan pending contact: %v", err)
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
		return status.Errorf(codes.Internal, "failed to get current user: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, c.status
		FROM contacts c
		JOIN users u ON c.contact_id = u.id
		WHERE c.user_id = $1
		ORDER BY u.username`,
		currentUserID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get contacts for updates: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username, contactStatus string
		if err := rows.Scan(&username, &contactStatus); err != nil {
			return status.Errorf(codes.Internal, "failed to scan contact for updates: %v", err)
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

	return nil
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
		return nil, status.Errorf(codes.Internal, "failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	var currentUserID, contactUserID string
	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", currentUser).Scan(&currentUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get current user: %v", err)
	}

	err = tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = $1", contactUsername).Scan(&contactUserID)
	if err == sql.ErrNoRows {
		return &pb.CommonResponse{
			Success: false,
			Message: "Контакт не найден",
		}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get contact user: %v", err)
	}

	result, err := tx.ExecContext(ctx, `
		DELETE FROM contacts 
		WHERE (user_id = $1 AND contact_id = $2) 
		   OR (user_id = $2 AND contact_id = $1)`,
		currentUserID, contactUserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove contact: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return &pb.CommonResponse{
			Success: false,
			Message: "Контакт не найден",
		}, nil
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit transaction: %v", err)
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Контакт успешно удален",
	}, nil
}

func main() {
	fmt.Println("Starting...")

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
	contactsService := NewContactsService(db)

	go authService.startSessionCleanup()

	server := grpc.NewServer(
		grpc.UnaryInterceptor(AuthMiddleware(authService)), grpc.StreamInterceptor(AuthStreamMiddleware(authService)),
	)

	pb.RegisterAuthServiceServer(server, authService)
	pb.RegisterContactServiceServer(server, contactsService)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("port 50051")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
