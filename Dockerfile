# syntax=docker/dockerfile:1.7

FROM golang:1.23 AS builder
WORKDIR /src

# Cache mod download layer
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o potat-api ./

FROM gcr.io/distroless/base-debian12 AS runner
WORKDIR /app

COPY --from=builder /src/potat-api /app/potat-api
COPY exampleconfig.json /app/exampleconfig.json
COPY --from=builder /src/haste/static /app/haste/static

EXPOSE 8080

ENTRYPOINT ["/app/potat-api"]
