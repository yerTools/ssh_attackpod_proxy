FROM golang:1.24-alpine3.22 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o ssh_attackpod_proxy ./main.go


FROM alpine:3.22

WORKDIR /app

COPY --from=builder /app/ssh_attackpod_proxy /app/ssh_attackpod_proxy

ENV NETWATCH_COLLECTOR_PROXIED_URL=
ENV NETWATCH_PROXY_LISTEN_ADDRESS=8161
ENV NETWATCH_PROXY_DB_PATH=/app/data/attacks.db

VOLUME /app/data

EXPOSE 8161

ENTRYPOINT ["/app/ssh_attackpod_proxy"]