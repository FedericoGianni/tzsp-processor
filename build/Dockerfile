# Build stage
FROM golang:1.27 AS builder
ARG VERSION=dev
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /app/bin/tzsp-processor ./cmd/tzsp-processor

# Final stage
FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app

COPY --from=builder /app/bin/tzsp-processor /app/tzsp-processor
EXPOSE 37008/udp
ENTRYPOINT ["/app/tzsp-processor"]