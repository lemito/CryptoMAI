package main

import (
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/lemito/CryptoMAI/proto"
)

func main() {
	log.Println("Starting...")

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
	chatService := NewChatService(db)
	conf := RabbitMQConfig{
		URL:      "amqp://guest:guest@localhost:5672/",
		Exchange: "chat_exchange",
	}
	msgService, err := NewMessagingService(conf, db, authService)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	defer msgService.Close()

	go authService.startSessionCleanup()
	go chatService.startChatCleanup()

	server := grpc.NewServer(
		grpc.UnaryInterceptor(AuthMiddleware(authService)),
		grpc.StreamInterceptor(AuthStreamMiddleware(authService)),
	)

	pb.RegisterAuthServiceServer(server, authService)
	pb.RegisterContactServiceServer(server, contactsService)
	pb.RegisterChatServiceServer(server, chatService)
	pb.RegisterMessagingServiceServer(server, msgService)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("port 50051")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
