#!/bin/sh
GOPRIVATE=github.com/oss-fun/netlink go get github.com/oss-fun/netlink
go mod tidy

CGO_ENABLED=0 go build -o ./bin/ -buildvcs=false ./cmd/calico-felix
