#!/bin/sh
CGO_ENABLED=0 go build -o ./bin/ -buildvcs=false ./cmd/calico-felix
