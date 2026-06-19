# Stage 1: build
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /alipan-tv-token main.go

# Stage 2: run
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Shanghai
ENV PORT=3000

COPY --from=builder /alipan-tv-token /alipan-tv-token

EXPOSE 3000

ENTRYPOINT ["/alipan-tv-token"]
