FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o ssh_attackpod_proxy ./main.go


FROM scratch

WORKDIR /app

COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/ssh_attackpod_proxy /app/ssh_attackpod_proxy

EXPOSE 8161

ENTRYPOINT ["/app/ssh_attackpod_proxy"]