//go:build freebsd

package ipfw

import (
	"fmt"
	"strings"
)

type NatConfig struct {
	number  int
	options []string
}

func NewNatCondig(number int) NatConfig {
	return NatConfig {
		number: number,
	}
}

func (nc NatConfig) CmdString() string {
	return fmt.Sprintf("nat %d config %s", nc.number, strings.Join([]string(nc.options), " "))
}

func (nc NatConfig) Ip(ip string) NatConfig {
	nc.options = append(nc.options, fmt.Sprintf("ip %s", ip))
	return nc
}

func (nc NatConfig) Iface(iface string) NatConfig {
	nc.options = append(nc.options, fmt.Sprintf("if %s", iface))
	return nc
}

func (nc NatConfig) Log() NatConfig {
	nc.options = append(nc.options, "log")
	return nc
}

func (nc NatConfig) Reset() NatConfig {
	nc.options = append(nc.options, "reset")
	return nc
}

func (nc NatConfig) log() NatConfig {
	nc.options = append(nc.options, "log")
	return nc
}

func (nc NatConfig) UnregOnly() NatConfig {
	nc.options = append(nc.options, "unreg_only")
	return nc
}

func (nc NatConfig) RedurectPort(localIP string, localPort, PublicPort int) NatConfig {
	nc.options = append(nc.options, fmt.Sprintf("redirect_port %s:%d %d", localIP, localPort, PublicPort))
	return nc
}

func (nc NatConfig) RedurectAddr(localIP, PublicIP string) NatConfig {
	nc.options = append(nc.options, fmt.Sprintf("redirect_addr %s %s", localIP, PublicIP))
	return nc
}

