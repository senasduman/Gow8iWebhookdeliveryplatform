FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/webhook-api ./cmd/api
FROM alpine:3.22
RUN adduser -D -H app
USER app
COPY --from=build /out/webhook-api /webhook-api
EXPOSE 8080
ENTRYPOINT ["/webhook-api"]
