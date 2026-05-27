FROM golang:1.22-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/oauth2smtp ./cmd/oauth2smtp

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=build /out/oauth2smtp /usr/local/bin/oauth2smtp

EXPOSE 2525

ENTRYPOINT ["oauth2smtp"]
CMD ["serve", "--config", "/config/config.yaml"]
