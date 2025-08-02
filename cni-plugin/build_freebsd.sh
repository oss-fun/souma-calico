#!/bin/sh

GOPRIVATE=github.com/oss-fun/netlink go get github.com/oss-fun/netlink@souma-dev
go mod tidy
go mod vendor

go build ./cmd/calico

sudo cp ./calico /opt/cni/bin/
sudo mv ./calico /usr/local/libexec/cni/
