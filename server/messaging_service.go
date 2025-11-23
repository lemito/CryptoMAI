package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	pb "github.com/lemito/CryptoMAI/proto"
	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type MessagingService struct {
	pb.UnimplementedMessagingServiceServer

	rabbitConn  *amqp.Connection
	db          *sql.DB
	authService *authService

	queues   map[string]bool
	queuesMu sync.RWMutex

	channelPool chan *amqp.Channel
	poolSize    int
	closeOnce   sync.Once

	activeSubscriptions map[string]context.CancelFunc
	subscriptionsMu     sync.RWMutex
}

func (s *MessagingService) setupRabbit(exchange string) error {
	ch, err := s.rabbitConn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	return ch.ExchangeDeclare(
		exchange,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
}

func NewMessagingService(conf RabbitMQConfig, db *sql.DB, service *authService) (*MessagingService, error) {
	conn, err := amqp.Dial(conf.URL)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к RabbitMQ: %v", err)
	}

	if conf.PoolSize <= 0 {
		conf.PoolSize = 52
	}

	serv := &MessagingService{
		rabbitConn:          conn,
		db:                  db,
		authService:         service,
		queues:              make(map[string]bool),
		channelPool:         make(chan *amqp.Channel, conf.PoolSize),
		poolSize:            conf.PoolSize,
		activeSubscriptions: make(map[string]context.CancelFunc),
	}

	for i := 0; i < conf.PoolSize; i++ {
		ch, err := conn.Channel()
		if err != nil {
			for j := 0; j < i; j++ {
				<-serv.channelPool
			}
			close(serv.channelPool)
			conn.Close()
			return nil, fmt.Errorf("не удалось создать канал RabbitMQ для пула: %v", err)
		}
		serv.channelPool <- ch
	}

	if err := serv.setupRabbit(conf.Exchange); err != nil {
		serv.Close()
		return nil, fmt.Errorf("не удалось настроить RabbitMQ: %v", err)
	}

	log.Printf("MessagingService запущен с RabbitMQ (пул каналов: %d) и PostgreSQL", conf.PoolSize)
	go func() {
		closeChan := serv.rabbitConn.NotifyClose(make(chan *amqp.Error))
		for err := range closeChan {
			log.Printf("Соединение с RabbitMQ разорвано: %v", err)
		}
	}()
	return serv, nil
}

func (s *MessagingService) getChannel() (*amqp.Channel, error) {
	select {
	case ch := <-s.channelPool:
		return ch, nil
	case <-time.After(5 * time.Second):
		return nil, status.Error(codes.ResourceExhausted, "таймаут получения канала RabbitMQ")
	}
}

func (s *MessagingService) releaseChannel(ch *amqp.Channel) {
	if ch == nil {
		return
	}

	select {
	case s.channelPool <- ch:
	default:
		ch.Close()
	}
}

func (s *MessagingService) closeAllChannels() {
	s.closeOnce.Do(func() {
		close(s.channelPool)
		for ch := range s.channelPool {
			if ch != nil {
				ch.Close()
			}
		}
	})
}

func (s *MessagingService) userHasAccessToChat(username, chatID string) bool {
	var cnt int
	query := `
    	SELECT COUNT(*) FROM chats c
        JOIN user_chats uc ON c.id = uc.chat_id
        WHERE c.id = $1 AND c.is_active = true 
        AND uc.username = $2 AND uc.is_active = true`

	err := s.db.QueryRow(query, chatID, username).Scan(&cnt)
	if err != nil {
		log.Printf("Ошибка: %v", err)
		return false
	}
	return cnt > 0
}

func (s *MessagingService) getChatParticipants(chatID string) ([]string, error) {
	query := `
        SELECT u1.username, u2.username
        FROM chats c
        JOIN users u1 ON c.initiator_username = u1.username
        JOIN users u2 ON c.participant_username = u2.username
        WHERE c.id = $1 AND c.is_active = true`

	var initiator, participant string
	err := s.db.QueryRow(query, chatID).Scan(&initiator, &participant)
	if err != nil {
		log.Printf("Ошибка проверки чата: %v", err)
		return nil, err
	}
	return []string{initiator, participant}, nil
}

func (s *MessagingService) createUserQueue(username string) error {
	queueName := "user." + username

	s.queuesMu.RLock()
	if s.queues[queueName] {
		s.queuesMu.RUnlock()
		return nil
	}
	s.queuesMu.RUnlock()

	s.queuesMu.Lock()
	defer s.queuesMu.Unlock()

	if s.queues[queueName] {
		return nil
	}

	ch, err := s.getChannel()
	if err != nil {
		return err
	}
	defer s.releaseChannel(ch)

	_, err = ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	err = ch.QueueBind(queueName, "user."+username, "chat_exchange", false, nil)
	if err != nil {
		return err
	}

	s.queues[queueName] = true
	log.Printf("Создана очередь для пользователя: %s", queueName)
	return nil
}

func (s *MessagingService) SendChunks(stream pb.MessagingService_SendChunksServer) error {
	authctx, err := GetAuthContext(stream.Context())
	if err != nil {
		return err
	}

	username := authctx.Username

	ch, err := s.getChannel()
	if err != nil {
		return status.Error(codes.Internal, "не удалось получить канал RabbitMQ из пула")
	}
	defer s.releaseChannel(ch)

	if err := ch.Confirm(false); err != nil {
		return status.Error(codes.Internal, "не удалось включить режим подтверждения")
	}

	confirms := ch.NotifyPublish(make(chan amqp.Confirmation, 100))
	ctx := stream.Context()

	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "клиент разорвал соединение")
		default:
			chunk, err := stream.Recv()
			if err != nil {
				if err.Error() == "EOF" {
					return nil
				}
				return status.Errorf(codes.Internal, "ошибка получения данных от клиента: %v", err)
			}

			if !s.userHasAccessToChat(username, chunk.Metadata.ChatId) {
				ack := &pb.ChunkAcknowledgement{
					FileId:     chunk.Metadata.FileId,
					ChunkIndex: chunk.Metadata.ChunkIndex,
					Success:    false,
					Error:      "доступ к чату запрещен",
				}
				if err := stream.Send(ack); err != nil {
					return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
				}
				continue
			}

			participants, err := s.getChatParticipants(chunk.Metadata.ChatId)
			if err != nil {
				ack := &pb.ChunkAcknowledgement{
					FileId:     chunk.Metadata.FileId,
					ChunkIndex: chunk.Metadata.ChunkIndex,
					Success:    false,
					Error:      "не удалось получить участников чата",
				}
				if err := stream.Send(ack); err != nil {
					return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
				}
				continue
			}

			messageBody, err := proto.Marshal(chunk)
			if err != nil {
				ack := &pb.ChunkAcknowledgement{
					FileId:     chunk.Metadata.FileId,
					ChunkIndex: chunk.Metadata.ChunkIndex,
					Success:    false,
					Error:      "не удалось маршализовать сообщение",
				}
				if err := stream.Send(ack); err != nil {
					return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
				}
				continue
			}

			for _, participant := range participants {
				if participant != username {
					if err := s.createUserQueue(participant); err != nil {
						log.Printf("Предупреждение: не удалось создать очередь для %s: %v", participant, err)
					}
				}
			}

			var successCount int
			var wg sync.WaitGroup

			for _, participant := range participants {
				if participant == username {
					continue
				}

				wg.Add(1)
				go func(recipient string) {
					defer wg.Done()

					err := ch.PublishWithContext(ctx,
						"chat_exchange",
						"user."+recipient,
						true,
						false,
						amqp.Publishing{
							ContentType:  "application/protobuf",
							Body:         messageBody,
							DeliveryMode: amqp.Persistent,
							Timestamp:    time.Now(),
							Headers: amqp.Table{
								"sender":     username,
								"chat_id":    chunk.Metadata.ChatId,
								"message_id": chunk.Metadata.MessageId,
								"file_id":    chunk.Metadata.FileId,
							},
						},
					)
					if err != nil {
						log.Printf("Не удалось опубликовать для пользователя %s: %v", recipient, err)
					} else {
						successCount++
					}
				}(participant)
			}

			wg.Wait()

			select {
			case confirm := <-confirms:
				if confirm.Ack && successCount > 0 {
					ack := &pb.ChunkAcknowledgement{
						FileId:     chunk.Metadata.FileId,
						ChunkIndex: chunk.Metadata.ChunkIndex,
						Success:    true,
					}
					if err := stream.Send(ack); err != nil {
						return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
					}
				} else {
					ack := &pb.ChunkAcknowledgement{
						FileId:     chunk.Metadata.FileId,
						ChunkIndex: chunk.Metadata.ChunkIndex,
						Success:    false,
						Error:      "сообщение не доставлено",
					}
					if err := stream.Send(ack); err != nil {
						return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
					}
				}
			case <-time.After(5 * time.Second):
				ack := &pb.ChunkAcknowledgement{
					FileId:     chunk.Metadata.FileId,
					ChunkIndex: chunk.Metadata.ChunkIndex,
					Success:    false,
					Error:      "таймаут подтверждения публикации",
				}
				if err := stream.Send(ack); err != nil {
					return status.Errorf(codes.Internal, "ошибка отправки подтверждения: %v", err)
				}
			}
		}
	}
}

func (s *MessagingService) SubscribeToChunks(req *pb.SubscribeToChunksRequest, stream pb.MessagingService_SubscribeToChunksServer) error {
	authctx, err := GetAuthContext(stream.Context())
	if err != nil {
		return err
	}

	username := authctx.Username
	chatId := req.ChatId

	log.Printf("Пользователь %s подписывается на сообщения чата %s", username, chatId)

	if err := s.createUserQueue(username); err != nil {
		return status.Error(codes.Internal, "не удалось создать очередь пользователя: "+err.Error())
	}

	ch, err := s.getChannel()
	if err != nil {
		return status.Error(codes.Internal, "не удалось получить канал RabbitMQ из пула")
	}

	queueName := "user." + username
	consumerTag := fmt.Sprintf("%s-%s-%d", username, chatId, time.Now().UnixNano())

	msgs, err := ch.Consume(
		queueName,
		consumerTag,
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		s.releaseChannel(ch)
		return status.Errorf(codes.Internal, "не удалось подписаться на сообщения: %v", err)
	}

	log.Printf("Пользователь %s подписался на получение сообщений из очереди %s", username, queueName)

	ctx := stream.Context()

	s.subscriptionsMu.Lock()
	if cancel, exists := s.activeSubscriptions[consumerTag]; exists {
		cancel()
	}

	subCtx, cancel := context.WithCancel(ctx)
	s.activeSubscriptions[consumerTag] = cancel
	s.subscriptionsMu.Unlock()

	defer func() {
		s.subscriptionsMu.Lock()
		delete(s.activeSubscriptions, consumerTag)
		s.subscriptionsMu.Unlock()

		ch.Cancel(consumerTag, false)
		s.releaseChannel(ch)
		log.Printf("Пользователь %s отписался от получения сообщений", username)
	}()

	for {
		select {
		case <-subCtx.Done():
			return nil
		case msg, ok := <-msgs:
			if !ok {
				return status.Error(codes.Internal, "соединение с RabbitMQ потеряно")
			}

			var chunk pb.EncryptedChunk
			if err := proto.Unmarshal(msg.Body, &chunk); err != nil {
				log.Printf("Не удалось демаршализовать сообщение: %v", err)
				msg.Nack(false, false)
				continue
			}

			if chatId != "" && chunk.Metadata.ChatId != chatId {
				msg.Ack(false)
				continue
			}

			if err := stream.Send(&chunk); err != nil {
				log.Printf("Ошибка отправки сообщения клиенту: %v", err)
				msg.Nack(false, true)
				return status.Errorf(codes.Internal, "ошибка отправки сообщения клиенту: %v", err)
			}

			msg.Ack(false)
			log.Printf("Сообщение доставлено пользователю %s из чата %s", username, chunk.Metadata.ChatId)
		}
	}
}

func (s *MessagingService) CancelTransfer(ctx context.Context, req *pb.TransferCancellation) (*pb.CommonResponse, error) {
	authctx, err := GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	username := authctx.Username

	if !s.userHasAccessToChat(username, req.ChatId) {
		return &pb.CommonResponse{
			Success: false,
			Message: "Пользователь не состоит в чате",
		}, nil
	}

	participants, err := s.getChatParticipants(req.ChatId)
	if err != nil {
		return &pb.CommonResponse{
			Success: false,
			Message: "Не удалось получить участников чата",
		}, nil
	}

	chunk := &pb.EncryptedChunk{
		Metadata: &pb.ChunkMetadata{
			ChatId:         req.ChatId,
			MessageId:      req.MessageId,
			FileId:         req.FileId,
			IsCancellation: true,
			Timestamp:      timestamppb.Now(),
		},
	}

	messageBody, err := proto.Marshal(chunk)
	if err != nil {
		return &pb.CommonResponse{
			Success: false,
			Message: "Ошибка обработки запроса",
		}, status.Error(codes.Internal, "ошибка сериализации")
	}

	ch, err := s.getChannel()
	if err != nil {
		return &pb.CommonResponse{
			Success: false,
			Message: "Сервис временно недоступен",
		}, status.Error(codes.Internal, "не удалось получить канал RabbitMQ")
	}
	defer s.releaseChannel(ch)

	var successCount int32
	for _, participant := range participants {
		if participant == username {
			continue
		}

		err := ch.PublishWithContext(ctx,
			"chat_exchange",
			"user."+participant,
			true,
			false,
			amqp.Publishing{
				ContentType:  "application/protobuf",
				Body:         messageBody,
				DeliveryMode: amqp.Persistent,
				Timestamp:    time.Now(),
				Headers: amqp.Table{
					"sender":       username,
					"chat_id":      req.ChatId,
					"message_id":   req.MessageId,
					"file_id":      req.FileId,
					"cancellation": true,
				},
			},
		)

		if err != nil {
			log.Printf("Ошибка отправки отмены для %s: %v", participant, err)
		} else {
			successCount++
			log.Printf("Отмена передачи %s отправлена участнику %s", req.MessageId, participant)
		}
	}

	if successCount > 0 {
		return &pb.CommonResponse{
			Success: true,
			Message: "Отмена передачи отправлена",
		}, nil
	}

	return &pb.CommonResponse{
		Success: false,
		Message: "Не удалось отправить отмену ни одному участнику",
	}, nil
}

func (s *MessagingService) Close() {
	s.closeOnce.Do(func() {
		log.Println("Закрытие MessagingService...")

		s.subscriptionsMu.Lock()
		for _, cancel := range s.activeSubscriptions {
			cancel()
		}
		s.activeSubscriptions = make(map[string]context.CancelFunc)
		s.subscriptionsMu.Unlock()

		s.closeAllChannels()

		s.queuesMu.Lock()
		s.queues = make(map[string]bool)
		s.queuesMu.Unlock()

		if s.rabbitConn != nil {
			s.rabbitConn.Close()
		}
		log.Println("MessagingService успешно закрыт")
	})
}
