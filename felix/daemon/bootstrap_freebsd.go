package daemon

import (
        "github.com/projectcalico/calico/felix/config"
        "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
        "github.com/projectcalico/calico/typha/pkg/discovery"
)

func bootstrapWireguardAndFilterTyphaAddresses(
        _ *config.Config, _ clientv3.NodesClient, typhas []discovery.Typha,
) ([]discovery.Typha, error) {
        return typhas, nil 
} // no filtering

func bootstrapRemoveWireguard(_ *config.Config, _ clientv3.Interface) error {
        return nil 
} // no-op
