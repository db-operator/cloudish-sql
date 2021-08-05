# cloudish-sql

Cloudish-sql is a local mock for testing applications that use Google Cloud
SQL. It partially implements the [Cloud SQL Admin API](https://cloud.google.com/sql/docs/mysql/admin-api/rest) and
includes a mTLS proxy suitable for proxying requests to a local database backend.

## Quickstart

Cloudish-sql will typically be used in conjunction with a PostgreSQL or MySQL
container. This is best achieved with a tool such as docker-compose.

```yaml
version: "3.6"
services:
  postgres:
    image: postgres:11-alpine
    environment:
      POSTGRES_PASSWORD: "test1234"

  cloudish-sql:
    build: .
    ports:
      - "127.0.0.1:3307:3307"
      - "127.0.0.1:8080:8080"
    environment:
      LOG_LEVEL: "INFO"
    command:
      - --db-address=postgres:5432
```

`cloudish-sql` will persist database information across requests in a filesystem based store. So between tests you 
will have to use unique ids or remove and restart the service.

## Development

### Prerequisites

* [Go 1.16+](https://golang.org/dl/)
* Make
* [golangci-lint v1.40+](https://golangci-lint.run/usage/install/)
* Additional Go tools:
    * [gofumpt](https://github.com/mvdan/gofumpt)
    * [gofumports](https://github.com/mvdan/gofumpt)
    * [gci](https://github.com/daixiang0/gci)

### Build

To build `cloudish-sql`, simply run make without any arguments.

The resulting binary will be written to: `./target/cloudish-sql`.

```shell script
make
```

### Test

Before committing any code you should always lint and test your changes.

#### Code Linting

```shell script
make lint
```

#### Running the Tests

```shell script
make test
```