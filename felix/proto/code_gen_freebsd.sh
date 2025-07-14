#!/bin/sh

# sudo pkg install -y grpc
#
# go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# go install github.com/gogo/protobuf/protoc-gen-gogofaster@v1.3.2
# export PATH="$PATH:$HOME/go/bin"

protoc  -I. -Ithird_party --gogofaster_out=plugins=grpc:. felixbackend.proto

# vim .pb.go -> :%s/proto\./proto1\./g
