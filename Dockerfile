FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN apk update && apk upgrade
RUN go mod download
RUN go build -o SecureSling .
FROM alpine:latest
RUN apk update && apk upgrade && rm -rf /var/cache/*
RUN addgroup -S secureslinggroup && adduser -S secureslinguser -G secureslinggroup
WORKDIR /root/
COPY . .
COPY --from=builder /app/SecureSling .
RUN chown -R secureslinguser:secureslinggroup /root/
USER secureslinguser
EXPOSE 8080
CMD ["./SecureSling"]
