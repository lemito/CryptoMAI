package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/lemito/CryptoMAI/proto"
)

type User struct {
	Username    string
	Password    []byte
	SessionKeys map[string]bool
}

type authService struct {
	pb.UnimplementedAuthServiceServer
	users      map[string]*User
	usersMutex sync.RWMutex
}

func NewAuthService() *authService {
	return &authService{
		users: make(map[string]*User),
	}
}

func (s *authService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.CommonResponse, error) {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	_, exist := s.users[req.Username]
	if exist {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пользователь с таким именем уже существует",
		}, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Ошибка в bcrypt-hash: %v", err)
	}

	s.users[req.Username] = &User{
		Username:    req.Username,
		Password:    hash,
		SessionKeys: make(map[string]bool),
	}

	return &pb.CommonResponse{
		Success: true,
		Message: "Регистрация успешна",
	}, nil
}

func generateSecureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (s *authService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	s.usersMutex.RLock()
	user, exists := s.users[req.Username]
	s.usersMutex.RUnlock()

	if !exists {
		return &pb.AuthResponse{
			Success: false,
			Message: "Пользователь не найден",
		}, nil
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		return &pb.AuthResponse{
			Success: false,
			Message: "Неверный пароль",
		}, nil
	}

	token := generateSecureToken()

	s.usersMutex.Lock()
	user.SessionKeys[token] = true
	s.usersMutex.Unlock()

	return &pb.AuthResponse{
		Success:      true,
		SessionToken: token,
		Message:      "",
	}, nil
}

func main() {
	fmt.Println("Absolute =UwU=")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("%v", err)
	}

	server := grpc.NewServer()
	authService := NewAuthService()
	pb.RegisterAuthServiceServer(server, authService)

	err = server.Serve(lis)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
