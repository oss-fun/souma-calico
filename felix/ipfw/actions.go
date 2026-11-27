//go:build freebsd

package ipfw

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type Action interface {
	String() string
}

func AddLog(a Action) string {
	return a.String() + " log"
}

type Referrer interface {
	ReferencedChain() string
}

type AllowAction struct {
	TypeAllow struct{}
}

func (a AllowAction) String() string {
	return "allow"
}

type DenyAction struct {
	TypeDeny struct{}
}

func (a DenyAction) String() string {
	return "deny"
}

type CountAction struct {
	TypeCount struct{}
}

func (a CountAction) String() string {
	return "count"
}

type CallAction struct {
	TypeCall   struct{}
	Target     string
	RuleNumber uint16
}

func (a CallAction) String() string {
	if a.RuleNumber != 0 {
		return fmt.Sprintf("call %d", a.RuleNumber)
	}
	if a.Target != "" {
		c, ok := ChainNameToChain[a.Target]
		if ok {
			return fmt.Sprintf("call %d", c.Number)
		} else {
			n, err := SetNewNumber()
			if err != nil {
				log.WithError(err).Panic("CallAction: setNewNumber failed")
				return ""
			}
			SetChainNum(a.Target, n)
			return fmt.Sprintf("call %d", n)
		}
	}
	return "// failed callAction: no filed RuleNumber or Target"
}

func (a CallAction) ReferencedChain() string {
	if a.Target != "" {
		return a.Target
	}
	return fmt.Sprintf("%d", a.RuleNumber)
}

var _ Referrer = CallAction{}

type ReturnAction struct {
	TypeReturn struct{}
}

func (a ReturnAction) String() string {
	return "return"
}

// ReturnTagAction は tag を付けてから呼び出し元へ戻る（"return tag N"）。
// tag は動作の一部（ip_fw.h: O_TAG は ACTION_PTR 以降に置かれる）なので、
// このルールが record-state で作った動的ルールに check-state で一致したときも、
// tag を付けて戻る動作がそのまま実行される。
type ReturnTagAction struct {
	TypeReturnTag struct{}
	TagNumber     uint16
}

func (a ReturnTagAction) String() string {
	return fmt.Sprintf("return tag %d", a.TagNumber)
}

type SkiptoAction struct {
	TypeSkipto struct{}
	Target     string
	RuleNumber uint16
}

func (a SkiptoAction) String() string {
	if a.RuleNumber != 0 {
		return fmt.Sprintf("skipto %d", a.RuleNumber)
	}
	if a.Target != "" {
		if ChainNameToChain[a.Target].Number != 0 {
			return fmt.Sprintf("skipto %d", ChainNameToChain[a.Target].Number)
		} else {
			n, err := SetNewNumber()
			if err != nil {
				log.WithError(err).Panic("CallAction: setNewNumber failed")
				return ""
			}
			SetChainNum(a.Target, n)
			return fmt.Sprintf("skipto %d", n)
		}
	}
	return "// failed skiptoAction: no filed RuleNumber or Target"
}

func (a SkiptoAction) ReferencedChain() string {
	if a.Target != "" {
		return a.Target
	}
	return fmt.Sprintf("%d", a.RuleNumber)
}

var _ Referrer = SkiptoAction{}

type NatAction struct {
	TypeNat struct{}
	NatNumber uint16
}

func (a NatAction) String() string {
	return fmt.Sprintf("nat %d", a.NatNumber)
}

// CheckStateAction は動的ルールと照合する（"check-state [:flowname]"）。
// 一致すると、その動的ルールを作ったルールの動作を実行する。一致しなければ次のルールへ進む。
// ipfw(8): "Check-state rules do not have a body." のため、Rule.renderInner は条件部分を出力しない。
type CheckStateAction struct {
	TypeCheckState struct{}
	FlowName       string
}

func (a CheckStateAction) String() string {
	if a.FlowName != "" {
		return fmt.Sprintf("check-state :%s", a.FlowName)
	}
	return "check-state"
}

type TagAction struct {
	TypeTag struct{}
	TagNumber uint16
}

func (a TagAction) String() string {
	return fmt.Sprintf("count tag %d", a.TagNumber)
}

type UntagAction struct {
	TypeUntag struct{}
	TagNumber uint16
}

func (a UntagAction) String() string {
	return fmt.Sprintf("count untag %d", a.TagNumber)
}

type LogAction struct {
	TypeLog struct{}
}

func (a LogAction) String() string {
	return fmt.Sprintf("count log")
}
