PROJ=dex
ORG_PATH=github.com/chub
REPO_PATH=github.com/chub/coreos-dex
export PATH := $(PWD)/bin:$(PATH)

VERSION ?= $(shell ./scripts/git-version)

DOCKER_REPO=quay.io/coreos/dex
DOCKER_IMAGE=$(DOCKER_REPO):$(VERSION)

$( shell mkdir -p bin )
$( shell mkdir -p _output/images )
$( shell mkdir -p _output/bin )

user=$(shell id -u -n)
group=$(shell id -g -n)

export GOBIN=$(PWD)/bin

LD_FLAGS="-w -X $(REPO_PATH)/version.Version=$(VERSION)"

build: bin/dex bin/example-app bin/grpc-client

bin/dex: check-go-version
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/dex

bin/example-app: check-go-version
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/example-app

bin/grpc-client: check-go-version
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/examples/grpc-client

.PHONY: release-binary
release-binary:
	@go build -o /go/bin/dex -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/dex

.PHONY: revendor
revendor:
	@glide up -v
	@glide-vc --use-lock-file --no-tests --only-code

test:
	@go test -v -i $(shell go list ./... | grep -v '/vendor/')
	@go test -v $(shell go list ./... | grep -v '/vendor/')

testrace:
	@go test -v -i --race $(shell go list ./... | grep -v '/vendor/')
	@go test -v --race $(shell go list ./... | grep -v '/vendor/')

vet:
	@go vet $(shell go list ./... | grep -v '/vendor/')

fmt:
	@go fmt $(shell go list ./... | grep -v '/vendor/')

lint:
	@for package in $(shell go list ./... | grep -v '/vendor/' | grep -v '/api' | grep -v '/server/internal'); do \
      golint -set_exit_status $$package $$i || exit 1; \
	done

_output/bin/dex:
	@./scripts/docker-build
	@sudo chown $(user):$(group) _output/bin/dex

.PHONY: docker-image
docker-image: clean-release _output/bin/dex
	@sudo docker build -t $(DOCKER_IMAGE) .

.PHONY: proto
proto: api/api.pb.go server/internal/types.pb.go

api/api.pb.go: api/api.proto bin/protoc bin/protoc-gen-go
	@./bin/protoc --go_out=plugins=grpc:. --plugin=protoc-gen-go=./bin/protoc-gen-go api/*.proto

server/internal/types.pb.go: server/internal/types.proto bin/protoc bin/protoc-gen-go
	@./bin/protoc --go_out=. --plugin=protoc-gen-go=./bin/protoc-gen-go server/internal/*.proto

bin/protoc: scripts/get-protoc
	@./scripts/get-protoc bin/protoc

bin/protoc-gen-go:
	@go install -v $(REPO_PATH)/vendor/github.com/golang/protobuf/protoc-gen-go

.PHONY: check-go-version
check-go-version:
	@./scripts/check-go-version

clean: clean-release
	@rm -rf bin/

.PHONY: clean-release
clean-release:
	@rm -rf _output/

testall: testrace vet fmt lint

FORCE:

.PHONY: test testrace vet fmt lint testall
