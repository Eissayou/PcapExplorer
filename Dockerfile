# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

# Stage 2: Build Backend
FROM golang:1.24-alpine AS backend-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 for static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server .

# Stage 3: Final
FROM alpine:latest
WORKDIR /app
# Install CA certs
RUN apk --no-cache add ca-certificates
# Copy frontend dist
COPY --from=frontend-builder /app/dist ./frontend/dist
# Copy backend binary
COPY --from=backend-builder /app/server .
# Copy the GeoLite2 database so the map works in the deployed container.
# The file is git-ignored (MaxMind license) but present in the local build
# context, so it is baked into the image at build time, not committed to git.
COPY data/ ./data/

# Run as a non-root user
RUN adduser -D -u 10001 appuser
USER appuser

EXPOSE 5432
CMD ["./server"]
