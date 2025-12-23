package main

import (
	"context"

	pb "github.com/lemito/CryptoMAI/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	SessionTokenHeader = "x-session-token"
)

func AuthMiddleware(log *zap.SugaredLogger, authService *authService) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		publicMethods := map[string]bool{
			"/chat.AuthService/Register":      true,
			"/chat.AuthService/Login":         true,
			"/chat.AuthService/ValidateToken": true,
		}

		log.Infof("Метод %s вызван", info.FullMethod)

		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		log.Infof("Метод %s вызван, но нуждается в авторизации", info.FullMethod)

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

		log.Infof("Контекст для %s создан", user.Username)
		authContext := &AuthContext{
			UserID:       user.ID.String(),
			Username:     user.Username,
			SessionToken: sessionToken,
		}

		ctx = context.WithValue(ctx, AuthContextKey{}, authContext)
		return handler(ctx, req)
	}
}

func AuthStreamMiddleware(log *zap.SugaredLogger, authService *authService) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		publicMethods := map[string]bool{}
		log.Infof("Stream method called: %s", info.FullMethod)

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
			log.Errorf("ошибка %s: %v", info.FullMethod, err)
			return err
		}

		authContext := &AuthContext{
			UserID:       user.ID.String(),
			Username:     user.Username,
			SessionToken: sessionToken,
		}

		ctx := context.WithValue(stream.Context(), AuthContextKey{}, authContext)

		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		log.Infof("Авторизация для потока %s, user: %s", info.FullMethod, authContext.Username)

		return handler(srv, wrappedStream)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
