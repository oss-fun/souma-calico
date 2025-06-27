package ipfw

import (
	"strings"
	"strconv"

	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
)

type Rule struct {
	Number  uint16
	Action  Action
	Match   MatchCriteria
	Comment []string
}

func (r Rule) RenderRaw(prefixFragment string) string {
	fragments := []string{}
	fragments = append(fragments, append(cmdshim.ADD_COMMAND, strconv.Itoa(int(r.Number)))...)
	return r.renderInner(fragments, prefixFragment)
}

func (r Rule) RenderAppend(chain Chain, prefixFragment string) string {
	fragments := []string{}
	ruleNum := strconv.Itoa(int(chain.GetStartRuleNum()))
	fragments = append(fragments, append(cmdshim.ADD_COMMAND, ruleNum)...)
	return r.renderInner(fragments, prefixFragment)
}

func (r Rule) renderInner(fragments []string, prefixFragment string) string {
	if prefixFragment != "" {
		fragments = append(fragments, prefixFragment)
	}
	if r.Action != nil {
		actionFragment := r.Action.String()
		if actionFragment != "" {
			fragments = append(fragments, actionFragment)
		}
	}
	matchFragment := r.Match.Render()
	if matchFragment != "" {
		fragments = append(fragments, matchFragment)
	}
	return strings.Join(fragments, " ")
}

type Chain struct {
	Name string
	Rules []Rule
}

func (c *Chain) GetStartRuleNum() uint16 {
	if len(c.Rules) <= 0 {
		return 0
	} else {
		return c.Rules[0].Number
	}
}

func (c *Chain) GetFinRuleNum() uint16 {
	return c.Rules[len(c.Rules)-1].Number
}

