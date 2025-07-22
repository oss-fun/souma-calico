package rules

import (
	. "github.com/projectcalico/calico/felix/ipfw"
	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
)

func SetDefaultMasqConfig(iface string) error {
	masq := NewNatConfig(GetNatRuleNumber("Default MASQUERADE Config")).Iface(iface).Reset().UnregOnly()
	
	if err := cmdshim.NewRealCmd(masq.CmdString()).Run(); err != nil {
		return err
	}
	return nil
}

