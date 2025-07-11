//go:build freebsd

package ipfw

import (
	"fmt"
)

type Action interface {
	String() string
}

func AddLog(a Action) string {
	return a.String() + " log"
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
	return fmt.Sprintf("call %d", a.RuleNumber)
}

type ReturnAction struct {
	TypeReturn struct{}
}

func (a ReturnAction) String() string {
	return "return"
}

type SkiptoAction struct {
	TypeSkipto struct{}
	Target     string
	RuleNumber uint16
}

func (a SkiptoAction) String() string {
	return fmt.Sprintf("skipto %d", a.RuleNumber)
}

type NatAction struct {
	TypeNat struct{}
	NatNumber uint16
}

func (a NatAction) String() string {
	return fmt.Sprintf("nat %d", a.NatNumber)
}

type CheckStateAction struct {
	TypeCheckState struct{}
}

func (a CheckStateAction) String() string {
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

