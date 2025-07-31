#!/bin/sh

go build ./cmd/calico

sudo cp ./calico /opt/cni/bin/
sudo mv ./calico /usr/local/libexec/cni/
