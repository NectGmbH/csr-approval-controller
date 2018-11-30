TAG=latest

export GOOS=linux

all: build docker-build

build:
	go build

docker-build:
	docker build -t kavatech/csr-approval-controller:$(TAG) .

docker-push:
	docker push kavatech/csr-approval-controller:$(TAG)
