package main

import (
	"context"
	"errors"
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

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	var sugar *zap.SugaredLogger = logger.Sugar()

	sugar.Info("Starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		sugar.Errorf("Failed to initialize database: %v", err)
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

	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		sugar.Errorf("Failed to listen: %v", err)
	}

	sugar.Infof("Server listening on port 50051")

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
		case <-time.After(15 * time.Second):
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
