FROM golang:1.26-alpine AS build

WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/sftp-proxy ./cmd/sftp-proxy

FROM alpine:3.22

RUN apk add --no-cache ca-certificates openssh-keygen && \
    adduser -D -H -u 10001 sftpproxy && \
    install -d -m 0700 -o sftpproxy -g sftpproxy /staging
COPY --from=build /out/sftp-proxy /usr/local/bin/sftp-proxy

USER sftpproxy
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/sftp-proxy"]
CMD ["-config", "/config/config.json"]