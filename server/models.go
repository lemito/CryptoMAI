package main

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

type AuthContextKey struct{}

type Chat struct {
	ID          string
	Initiator   string
	Participant string
	Algorithm   pb.EncryptionAlgorithm
	Mode        pb.EncryptionMode
	Padding     pb.PaddingMode
	BaseIV      []byte
	InitiatorDH DHParams
	PeerDH      *DHParams
	IsActive    bool
	CreatedAt   time.Time
}

type DHParams struct {
	Prime     []byte
	Generator []byte
	PublicKey []byte
}

type UserChat struct {
	UserID   string
	ChatID   string
	Username string
	IsActive bool
	JoinedAt time.Time
	LeftAt   *time.Time
}

type RabbitMQConfig struct {
	URL      string
	Exchange string
	PoolSize int
}

func GetAuthContext(ctx context.Context) (*AuthContext, error) {
	authContext, ok := ctx.Value(AuthContextKey{}).(*AuthContext)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Контекст аутентификации не найден")
	}
	return authContext, nil
}