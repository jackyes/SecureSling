FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN apk update && apk upgrade
RUN go get -u -v all
RUN go mod download
RUN go build -o SecureSling .
FROM alpine:latest
RUN apk update && apk upgrade && rm -rf /var/cache/*
RUN addgroup -S secureslinggroup && adduser -S secureslinguser -G secureslinggroup
WORKDIR /root/
COPY . .
COPY --from=builder /app/SecureSling .
RUN mkdir uploads config
RUN chown -R secureslinguser:secureslinggroup /root/ uploads config
USER secureslinguser
EXPOSE 8080
CMD ["./SecureSling"]
