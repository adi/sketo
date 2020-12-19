FROM golang:1.15.6-alpine as build
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE on

WORKDIR /app
COPY go.* /app/
RUN apk update && apk upgrade && \
    apk add --no-cache git openssh build-base
RUN go mod download
COPY . .
RUN go build -o /out/go-app .

FROM alpine:3.12.0 as bin

COPY --from=build /out/go-app /bin/sketo
ENV STORAGE_DIR=/storage
ENV GOMAXPROCS=128
ENTRYPOINT ["/bin/sketo"]
