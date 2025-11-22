FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY proto/ ./proto/
COPY server/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates
COPY --from=builder /server /app/server
ENV TZ=Europe/Moscow
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/server"]