package main

import (
	"log"
	"go.uber.org/zap"
	"net"

	"google.golang.org/grpc"

	pb "github.com/lemito/CryptoMAI/proto"
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	var sugar *zap.SugaredLogger = logger.Sugar()

	sugar.Info("Starting...")

	dbConfig := DatabaseConfig{
		Host:     "db",
		Port:     "5432",
		User:     "meow",
		Password: "meow",
		DBName:   "cryptomai_db",
		SSLMode:  "disable",
	}

	db, err := initDB(sugar, dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	authService := NewAuthService(sugar, db)
	contactsService := NewContactsService(sugar, db)
	chatService := NewChatService(sugar, db)
	chatService.Start()

	conf := RabbitMQConfig{
		URL:      "amqp://guest:guest@rabbitmq:5672/",
		Exchange: "chat_exchange",
	}
	msgService, err := NewMessagingService(sugar, conf, db, authService)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	defer msgService.Close()

	go authService.startSessionCleanup()
	go chatService.startChatCleanup()

	server := grpc.NewServer(
		grpc.UnaryInterceptor(AuthMiddleware(sugar, authService)),
		grpc.StreamInterceptor(AuthStreamMiddleware(sugar, authService)),
	)

	pb.RegisterAuthServiceServer(server, authService)
	pb.RegisterContactServiceServer(server, contactsService)
	pb.RegisterChatServiceServer(server, chatService)
	pb.RegisterMessagingServiceServer(server, msgService)

	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		sugar.Errorf("Failed to listen: %v", err)
	}

	log.Println("port 50051")
	if err := server.Serve(lis); err != nil {
		sugar.Errorf("Failed to serve: %v", err)
	}
}
