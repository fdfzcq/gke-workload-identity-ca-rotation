FROM golang:alpine as builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build the app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ca-automation cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/ca-automation .
CMD ["./ca-automation"]
