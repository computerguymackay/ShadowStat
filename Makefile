BINARY := shadowstat
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X ShadowStat/internal/version.Version=$(VERSION)

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

.PHONY: run
run: build
	./bin/$(BINARY) run

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

# Grants the dev binary CAP_NET_RAW/CAP_NET_ADMIN so `make run` works without
# running the whole process as root. Mirrors what the (future) service-install
# subcommand will do for its dedicated service user.
.PHONY: setcap
setcap: build
	sudo setcap cap_net_raw,cap_net_admin+eip bin/$(BINARY)

.PHONY: clean
clean:
	rm -rf bin
