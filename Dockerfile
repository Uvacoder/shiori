# build stage
FROM golang:alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
RUN go build

# server image
FROM golang:alpine
COPY --from=builder /src/shiori /usr/local/bin/

ARG PGHOST
ARG PGPORT
ARG PGUSER
ARG PGPASSWORD
ARG PGDATABASE

ENV SHIORI_DBMS postgresql
ENV SHIORI_PG_USER $PGUSER
ENV SHIORI_PG_PASS $PGPASSWORD
ENV SHIORI_PG_NAME $PGDATABASE
ENV SHIORI_PG_HOST $PGHOST
ENV SHIORI_PG_PORT $PGPORT

EXPOSE 8080
CMD ["/usr/local/bin/shiori", "serve"]
