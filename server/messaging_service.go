package main

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/lemito/CryptoMAI/proto"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
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

	activeConsumers map[string]*ConsumerState
	consumersMu     sync.RWMutex

	isClosed atomic.Bool

	reconnectMu  sync.RWMutex
	reconnecting bool
	exchange     string
	rabbitURL    string

	logger *zap.SugaredLogger
}

type ConsumerState struct {
	ch          *amqp.Channel
	consumerTag string
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

func NewMessagingService(log *zap.SugaredLogger, conf RabbitMQConfig, db *sql.DB, service *authService) (*MessagingService, error) {
	conn, err := amqp.DialConfig(conf.URL, amqp.Config{
		Heartbeat: 60 * time.Second,
		Dial:      amqp.DefaultDial(time.Minute),
	})
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к RabbitMQ: %v", err)
	}

	if conf.PoolSize <= 0 {
		conf.PoolSize = 42
	}

	serv := &MessagingService{
		rabbitConn:          conn,
		db:                  db,
		authService:         service,
		queues:              make(map[string]bool),
		channelPool:         make(chan *amqp.Channel, conf.PoolSize),
		poolSize:            conf.PoolSize,
		activeSubscriptions: make(map[string]context.CancelFunc),
		activeConsumers:     make(map[string]*ConsumerState),
		exchange:            conf.Exchange,
		rabbitURL:           conf.URL,
		logger: log,
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

	serv.logger.Infof("MessagingService запущен с RabbitMQ (пул каналов: %d)", conf.PoolSize)

	go serv.monitorConnection()

	return serv, nil
}

func (s *MessagingService) monitorConnection() {
	closeChan := s.rabbitConn.NotifyClose(make(chan *amqp.Error, 1))
	for err := range closeChan {
		if err != nil {
			s.logger.Infof("Соединение с RabbitMQ разорвано: %v", err)
			s.reconnectMu.Lock()
			s.reconnecting = true
			s.reconnectMu.Unlock()

			s.closeAllSubscriptions()

			go s.reconnectWithBackoff()
		}
	}
}

func (s *MessagingService) reconnectWithBackoff() {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	maxRetries := 10

	for i := 0; i < maxRetries; i++ {
		s.logger.Infof("Попытка переподключения #%d к RabbitMQ через %v", i+1, backoff)
		time.Sleep(backoff)

		conn, err := amqp.Dial(s.rabbitURL)
		if err != nil {
			s.logger.Infof("Не удалось переподключиться: %v", err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		s.rabbitConn = conn
		s.reconnecting = false

		s.recreateChannelPool()

		if err := s.setupRabbit(s.exchange); err != nil {
			s.logger.Infof("Не удалось восстановить exchange: %v", err)
			conn.Close()
			continue
		}

		s.logger.Infof("Переподключение к RabbitMQ успешно")

		go s.monitorConnection()
		return
	}

	s.logger.Error("Не удалось переподключиться к RabbitMQ после нескольких попыток")
}

func (s *MessagingService) recreateChannelPool() {
	s.closeAllChannels()

	s.channelPool = make(chan *amqp.Channel, s.poolSize)
	for i := 0; i < s.poolSize; i++ {
		ch, err := s.rabbitConn.Channel()
		if err != nil {
			s.logger.Infof("Не удалось создать канал при переподключении: %v", err)
			continue
		}
		s.channelPool <- ch
	}
}

func (s *MessagingService) closeAllSubscriptions() {
	s.subscriptionsMu.Lock()
	defer s.subscriptionsMu.Unlock()

	for _, cancel := range s.activeSubscriptions {
		cancel()
	}
	s.activeSubscriptions = make(map[string]context.CancelFunc)

	s.logger.Infof("Все подписки закрыты из-за разрыва RabbitMQ соединения")
}

func (s *MessagingService) getChannel() (*amqp.Channel, error) {
	if s.isClosed.Load() {
		return nil, status.Error(codes.Unavailable, "MessagingService закрыт")
	}

	s.reconnectMu.RLock()
	if s.reconnecting {
		s.reconnectMu.RUnlock()
		return nil, status.Error(codes.Unavailable, "Переподключение к RabbitMQ")
	}
	s.reconnectMu.RUnlock()

	select {
	case ch := <-s.channelPool:
		if ch == nil || ch.IsClosed() {
			newCh, err := s.rabbitConn.Channel()
			if err != nil {
				return nil, status.Error(codes.Internal, "не удалось создать канал RabbitMQ")
			}
			return newCh, nil
		}
		return ch, nil
	case <-time.After(5 * time.Second):
		return nil, status.Error(codes.ResourceExhausted, "таймаут получения канала RabbitMQ")
	}
}

func (s *MessagingService) releaseChannel(ch *amqp.Channel) {
	if ch == nil {
		return
	}

	if s.isClosed.Load() || ch.IsClosed() {
		ch.Close()
		return
	}

	select {
	case s.channelPool <- ch:
	default:
		ch.Close()
		s.logger.Infof("Пул каналов переполнен, канал закрыт")
	}
}

func (s *MessagingService) closeAllChannels() {
	close(s.channelPool)
	for ch := range s.channelPool {
		if ch != nil {
			ch.Close()
		}
	}
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
		s.logger.Infof("Ошибка: %v", err)
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
		s.logger.Infof("Ошибка проверки чата: %v", err)
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

	err = ch.QueueBind(
		queueName,
		"user."+username,
		s.exchange,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	s.queues[queueName] = true
	s.logger.Infof("Создана очередь для пользователя: %s", queueName)
	return nil
}

func (s *MessagingService) SendChunks(stream pb.MessagingService_SendChunksServer) error {
	authctx, err := GetAuthContext(stream.Context())
	if err != nil {
		return err
	}

	s.reconnectMu.RLock()
	reconnecting := s.reconnecting
	s.reconnectMu.RUnlock()

	if reconnecting {
		return status.Error(codes.Unavailable, "Сервис переподключается к RabbitMQ, попробуйте позже")
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
						s.logger.Infof("Предупреждение: не удалось создать очередь для %s: %v", participant, err)
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
						s.exchange,
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
						s.logger.Infof("Не удалось опубликовать для пользователя %s: %v", recipient, err)
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

	s.reconnectMu.RLock()
	reconnecting := s.reconnecting
	s.reconnectMu.RUnlock()

	if reconnecting {
		return status.Error(codes.Unavailable, "Сервис переподключается к RabbitMQ, попробуйте позже")
	}

	s.logger.Infof("Пользователь %s подписывается на сообщения чата %s", username, chatId)

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

	s.logger.Infof("Пользователь %s подписался на получение сообщений из очереди %s для чата %s", username, queueName, chatId)

	ctx := stream.Context()

	s.subscriptionsMu.Lock()
	if cancel, exists := s.activeSubscriptions[consumerTag]; exists {
		cancel()
	}

	subCtx, cancel := context.WithCancel(ctx)
	s.activeSubscriptions[consumerTag] = cancel
	s.subscriptionsMu.Unlock()

	consumerState := &ConsumerState{
		ch:          ch,
		consumerTag: consumerTag,
	}
	s.consumersMu.Lock()
	s.activeConsumers[consumerTag] = consumerState
	s.consumersMu.Unlock()

	defer func() {
		s.subscriptionsMu.Lock()
		delete(s.activeSubscriptions, consumerTag)
		s.subscriptionsMu.Unlock()

		s.consumersMu.Lock()
		delete(s.activeConsumers, consumerTag)
		s.consumersMu.Unlock()

		if err := ch.Cancel(consumerTag, false); err != nil {
			s.logger.Infof("Ошибка при отмене %s: %v", consumerTag, err)
		}

		s.releaseChannel(ch)
		s.logger.Infof("Пользователь %s отписался от получения сообщений. ChatID: %s", username, chatId)
	}()

	for {
		select {
		case <-subCtx.Done():
			return nil
		case msg, ok := <-msgs:
			if !ok {
				s.logger.Infof("Канал сообщений закрыт для %s", username)
				return status.Error(codes.Internal, "соединение с RabbitMQ потеряно")
			}

			var chunk pb.EncryptedChunk
			if err := proto.Unmarshal(msg.Body, &chunk); err != nil {
				s.logger.Infof("Не удалось демаршализовать сообщение: %v", err)
				msg.Nack(false, false)
				continue
			}

			if chatId != "" && chunk.Metadata.ChatId != chatId {
				msg.Ack(false)
				continue
			}

			if err := stream.Send(&chunk); err != nil {
				s.logger.Infof("Ошибка отправки сообщения клиенту: %v", err)
				return status.Errorf(codes.Internal, "ошибка отправки сообщения клиенту: %v", err)
			}

			msg.Ack(false)
			s.logger.Infof("Сообщение доставлено пользователю %s из чата %s", username, chunk.Metadata.ChatId)
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
			s.exchange,
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
			s.logger.Infof("Ошибка отправки отмены для %s: %v", participant, err)
		} else {
			successCount++
			s.logger.Infof("Отмена передачи %s отправлена участнику %s", req.MessageId, participant)
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
		s.isClosed.Store(true)
		s.reconnecting = true

		s.logger.Infof("Закрытие MessagingService...")
		s.closeAllSubscriptions()

		time.Sleep(500 * time.Millisecond)

		s.consumersMu.Lock()
		for consumerTag, consumer := range s.activeConsumers {
			if consumer.ch != nil {
				if err := consumer.ch.Cancel(consumerTag, false); err != nil {
					s.logger.Infof("Ошибка при отмене %s: %v", consumerTag, err)
				}
			}
		}
		s.activeConsumers = make(map[string]*ConsumerState)
		s.consumersMu.Unlock()

		s.closeAllChannels()

		s.queuesMu.Lock()
		s.queues = make(map[string]bool)
		s.queuesMu.Unlock()

		if s.rabbitConn != nil {
			s.rabbitConn.Close()
		}
		s.logger.Infof("MessagingService успешно закрыт")
	})
}
