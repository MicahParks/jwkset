FROM golang:1 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" -o jwksetcom -trimpath cmd/server/*.go

FROM alpine
COPY --from=builder /app/jwksetcom /jwksetcom
ENV CONFIG_JSON='{}'
CMD ["/jwksetcom"]
