FROM golang:1 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" -o jwksetcom -trimpath cmd/server/*.go

# CA certificates required for reCAPTCHA verification on jwkset.com
FROM alpine:latest
COPY --from=builder /app/jwksetcom /jwksetcom
USER 10001
ENV CONFIG_JSON='{}'
CMD ["/jwksetcom"]
