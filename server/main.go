package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"google.golang.org/grpc"

	pb "github.com/lemito/CryptoMAI/proto"

	_ "go.uber.org/automaxprocs"
)

type ENVParams struct {
	rabbitURL string
	dbConfig  DatabaseConfig
	grpcPort  string
}

func GetENVParams(sugar *zap.SugaredLogger) (ENVParams, error) {
	sugar.Info("Start GetENVParams")
	url := os.Getenv("RABBITMQ_URL")
	if url == "" {
		sugar.Warn("GetENVParams: RABBITMQ_URL is empty")
		url = "amqp://guest:guest@rabbitmq:5672/"
	}

	portgrpc := os.Getenv("GRPC_PORT")
	if portgrpc == "" {
		sugar.Warn("GetENVParams: GRPC_PORT is empty")
		portgrpc = "50051"
	}

	config := DatabaseConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}
	if config.Host == "" {
		sugar.Warn("GetENVParams: DB_HOST is empty. Check ALL DB_ params")
	}

	return ENVParams{
		rabbitURL: url,
		dbConfig:  config,
		grpcPort:  portgrpc,
	}, nil
}

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	var sugar *zap.SugaredLogger = logger.Sugar()

	sugar.Info("Starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params, err := GetENVParams(sugar)
	if err != nil {
		sugar.Errorf("Error getting env parameters: %v", err)
	}

	db, err := initDB(sugar, params.dbConfig)
	if err != nil {
		sugar.Errorf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	authService := NewAuthService(sugar, db)
	contactsService := NewContactsService(sugar, db)
	chatService := NewChatService(sugar, db)
	chatService.Start()

	conf := RabbitMQConfig{
		URL:      params.rabbitURL,
		Exchange: "chat_exchange",
	}
	msgService, err := NewMessagingService(sugar, conf, db, authService)
	if err != nil {
		sugar.Errorf("Failed: %v", err)
	}
	defer msgService.Close()

	go authService.startSessionCleanup(ctx)
	go chatService.startChatCleanup(ctx)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(AuthMiddleware(sugar, authService)),
		grpc.StreamInterceptor(AuthStreamMiddleware(sugar, authService)),
	)

	pb.RegisterAuthServiceServer(server, authService)
	pb.RegisterContactServiceServer(server, contactsService)
	pb.RegisterChatServiceServer(server, chatService)
	pb.RegisterMessagingServiceServer(server, msgService)

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", params.grpcPort))
	if err != nil {
		sugar.Errorf("Failed to listen: %v", err)
	}

	sugar.Infof("Server listening on port %s", params.grpcPort)

	serverErr := make(chan error, 1)

	go func() {
		if err := server.Serve(lis); err != nil {
			if !errors.Is(err, grpc.ErrServerStopped) {
				serverErr <- err
			} else {
				serverErr <- nil
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	sugar.Info("Server is running. Press Ctrl+C to stop.")

	select {
	case sig := <-sigChan:
		sugar.Infof("Received signal: %v. Starting graceful shutdown...", sig)

		cancel()

		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			sugar.Info("Server stopped gracefully")
		case <-time.After(30 * time.Second):
			sugar.Warn("Graceful shutdown timed out, forcing stop")
			server.Stop()
		}

	case err := <-serverErr:
		if err != nil {
			sugar.Errorf("Server error: %v", err)
			cancel()
			time.Sleep(2 * time.Second)
		}
	}

	sugar.Info("Shutdown completed")

}
