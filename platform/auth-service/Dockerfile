FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-service .
EXPOSE 8081
CMD ["./auth-service"]
