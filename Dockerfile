FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN apk update && apk upgrade
RUN go mod download
RUN go build -o SecureSling .
FROM alpine:latest
RUN apk update && apk upgrade && rm -rf /var/cache/*
WORKDIR /root/
COPY . .
COPY --from=builder /app/SecureSling .
EXPOSE 8080
CMD ["./SecureSling"]
