BIN = target/cloudish-sql
SRC = $(shell find . -type f -name '*.go')

$(BIN): $(SRC)
	@mkdir -p target
	@go build -o $@ main.go

test: $(SRC)
	@go test ./...

lint: $(SRC)
	@go mod tidy
	@gofumpt -s -l -w $^
	@gci -w $^
	@golangci-lint run --timeout 5m0s --enable-all \
		-D gochecknoglobals -D exhaustivestruct -D wrapcheck -D interfacer -D maligned -D scopelint -D golint -D gomnd -D paralleltest ./...

clean:
	@-rm -Rf target/*
	@go clean -testcache

.PHONY: test lint clean