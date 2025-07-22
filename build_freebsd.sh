#!/bin/sh

# Task: developにマージしたことにより、ビルドができなくなったのでそれぞれのディレクトリを修正する。
# ・./felix
# ・./calicoctl
# ・./cni-plugin
#
# felix
# CGO_ENABLED=0 go build -o ./bin/ -buildvcs=false ./cmd/calico-felix/
#
# calicoctl
# go build -o ./bin/calicoctl ./calicoctl/calicoctl.go
#
# cni-plugin
# GOPRIVATE=github.com/oss-fun/plugins go get github.com/oss-fun/plugins/pkg/ipam
# GOPRIVATE=github.com/oss-fun/plugins go get github.com/oss-fun/plugins/pkg/ns
# GOPRIVATE=github.com/oss-fun/plugins go get github.com/oss-fun/plugins/pkg/ip
# go mod tidy
# go mod vendor
# ns_freebsd.goをgo/mod/containernetworking/cni@1.2.0/pkg/ns/に追加
# go build -o ./bin/calico ./cmd/calico

echo タスクやれ！！！
