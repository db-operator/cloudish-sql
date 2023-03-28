FROM golang:1.16.6-alpine3.14 as builder

ENV CGO_ENABLED=0

RUN apk add --update --no-cache make

WORKDIR /go/src/github.com/db-operator/cloudish-sql

# to reduce docker build time download dependency first before building
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN make

FROM alpine:3.14

COPY --from=builder /go/src/github.com/db-operator/cloudish-sql/target/cloudish-sql /usr/local/bin/cloudish-sql

EXPOSE 8080/tcp
ENTRYPOINT [ "/usr/local/bin/cloudish-sql" ]
