//go:build freebsd

package ipfw

import (
	"fmt"
	"strings"
)

type NatConfig struct {
	detail  string
	number  int
	options []string
}

var ActiveNatConfigToNumber map[int]string
var ActiveNumberToNatConfig map[string]int

func NewNatConfig(number int) NatConfig {
	return NatConfig {
		detail: ActiveNatConfigToNumber[number],
		number: number,
	}
}

func GetNatRuleNumber(d string) int {
	for i:=1; i<=65535; i++ {
		if ActiveNatConfigToNumber[i] == "" {
			ActiveNatConfigToNumber[i] = d
			ActiveNumberToNatConfig[d] = i
			return i
		}
	}
	return -1
}

func (nc NatConfig) CmdString() string {
	return fmt.Sprintf("ipfw nat %d config %s", nc.number, strings.Join([]string(nc.options), " "))
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

