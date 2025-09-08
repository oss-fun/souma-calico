//go:build freebsd

package ipfw

import (
	"fmt"
	"os"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"strconv"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
	"github.com/projectcalico/calico/felix/environment"
)

const (
	// Compromise: shorter is better for table occupancy and readability. Longer is better for
	// collision-resistance.  16 chars gives us 96 bits of entropy, which is fairly collision
	// resistant.
	HashLength = 16
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
	return r.renderInner(fragments, prefixFragment, nil)
}

func (r Rule) RenderAppend(chainName, prefixFragment string, features *environment.Features) string {
	//fmt.Printf("[souma-log] chainName: %v\n", chainName)
	fragments := []string{}
	fragments = append(fragments, append(cmdshim.ADD_COMMAND, strconv.Itoa(int(r.Number)))...)
	return r.renderInner(fragments, prefixFragment, features)
}

func (r Rule) RenderReplace(chainName string, ruleNum uint16, prefixFragment string, features *environment.Features) string {
	// ルール番号の特定
	chain, ok := ChainNameToChain[chainName]
	if !ok {
		log.Panic("ChainNameToChain Failed")
	}
	chainNum := chain.GetStartRuleNum()
	target := chainNum + ruleNum - 1

	// 既存のルールを削除するコマンド生成
	delRule := fmt.Sprintf("ipfw delete %d", target)

	// 新しいルールを追加するコマンド生成
	fragments := []string{}
	fragments = append(fragments, append(cmdshim.ADD_COMMAND, strconv.Itoa(int(target)))...)
	newRule := r.renderInner(fragments, prefixFragment, features)

	return fmt.Sprintf("%s\n%s", delRule, newRule)
}

func (r Rule) renderInner(fragments []string, prefixFragment string, features *environment.Features) string {
	if r.Action != nil {
		actionFragment := r.Action.String()
		if actionFragment != "" {
			fragments = append(fragments, actionFragment)
		}
	}
	matchFragment := r.Match.Render()
	if matchFragment != "" {
		fragments = append(fragments, matchFragment)
	} else {
		allPacketMatch := Match().SourceNet("any").DestNet("any").Render()
		fragments = append(fragments, allPacketMatch)
	}
	if len(r.Comment) > 0 {
		for _, c := range r.Comment {
			fragments = append(fragments, fmt.Sprintf("// %s", c))
		}
	}
	if prefixFragment != "" {
		fragments = append(fragments, prefixFragment)
	}
	return strings.Join(fragments, " ")
}

var shellUnsafe = regexp.MustCompile(`[^\w @%+=:,./#-]`)

func escapeComment(s string) string {
	return shellUnsafe.ReplaceAllString(s, "_")
}

const maxCommentLen = 256

func truncateComment(s string) string {
	if len(s) > maxCommentLen {
		return s[0:maxCommentLen]
	}
	return s
}

type Chain struct {
	Name string
	Number uint16
	Rules []Rule
}

func (c *Chain) RuleHashes(features *environment.Features) []string {
	if c == nil {
		return nil
	}
	hashes := make([]string, len(c.Rules))
	// First hash the chain name so that identical rules in different chains will get different
	// hashes.
	s := sha256.New224()
	_, err := s.Write([]byte(c.Name))
	if err != nil {
		log.WithFields(log.Fields{
			"chain": c.Name,
		}).WithError(err).Panic("Failed to write suffix to hash.")
		return nil
	}

	hash := s.Sum(nil)
	for ii, rule := range c.Rules {
		// Each hash chains in the previous hash, so that its position in the chain and
		// the rules before it affect its hash.
		s.Reset()
		_, err = s.Write(hash)
		if err != nil {
			log.WithFields(log.Fields{
				"action":   rule.Action,
				"position": ii,
				"chain":    c.Name,
			}).WithError(err).Panic("Failed to write suffix to hash.")
		}
		ruleForHashing := rule.RenderAppend(c.Name, "HASH", features)
		_, err = s.Write([]byte(ruleForHashing))
		if err != nil {
			log.WithFields(log.Fields{
				"ruleFragment": ruleForHashing,
				"action":       rule.Action,
				"position":     ii,
				"chain":        c.Name,
			}).WithError(err).Panic("Failed to write rule for hashing.")
		}
		hash = s.Sum(hash[0:0])
		// Encode the hash using a compact character set.  We use the URL-safe base64
		// variant because it uses '-' and '_', which are more shell-friendly.
		hashes[ii] = fmt.Sprintf("%s:%s", c.Name, base64.RawURLEncoding.EncodeToString(hash)[:HashLength])
		//hashes[ii] = base64.RawURLEncoding.EncodeToString(hash)[:HashLength]
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ruleFragment": ruleForHashing,
				"action":       rule.Action,
				"position":     ii,
				"chain":        c.Name,
				"hash":         hashes[ii],
			}).Debug("Hashed rule")
		}
	}
	return hashes
}

func (c *Chain) GetStartRuleNum() uint16 {
	switch {
	case c.Number != 0:
		return c.Number
	//case len(c.Rules) != 0:
	//	c.Number = c.Rules[0].Number
	//	return c.Number
	//case ChainNameToChain[c.Name] != 0:
	//	c.Number = ChainNameToChainNum[c.Name]
	//	return c.Number
	default:
		// log.Panic("GetStartRuleNum failed: no number found for chain ", c.Name)
		return 65535
	}
}

// chain番号とかルール番号の成形
func (c *Chain) Organize() error {
	if c == nil {
		return fmt.Errorf("Chain is nill")
	}

	// chain番号の生成
	start := c.GetStartRuleNum()
	if start == 65535 {
		n, err := SetNewNumber()
		start = n
		if err != nil {
			return fmt.Errorf("SetNewNumber failed: %v", err)
		}
	}
	c.Number = start

	// rulesの先頭にChain名のコメント行を入れる
	createChainRule := []Rule {
		{
			Action: CountAction{},
			//Comment: []string{fmt.Sprintf("chainName: %s", c.Name)},
		},
	}
	c.Rules = append(createChainRule, c.Rules...)

	// rule番号の生成
	for i, _ := range c.Rules {
		c.Rules[i].Number = c.Number + uint16(i)
	}

	_, ok := ChainNameToChain[c.Name]
	if !ok {
		ChainNameToChain[c.Name] = c
	}

	return nil
}

const (
	RULE_BUF = 10
)

// chain番号の生成
func SetNewNumber() (uint16, error) {
	var result uint16
	for _, c := range ChainNameToChain {
		n := c.Number
		if result < n {
			result = n
		}
	}
	result = result + RULE_BUF
	if result >= 65535 {
		return 0, fmt.Errorf("No Enough Chain Num")
	}

	return result, nil
}

func (c *Chain) GetFinRuleNum() uint16 {
	return c.Rules[len(c.Rules)-1].Number
}

func (c *Chain) GetNextRuleNum() uint16 {
	return c.GetFinRuleNum()+1
}

func (c *Chain) IpfwTableNames() (ipfwTableNames []string) {
	if c == nil {
		return nil
	}
	for _, rule := range c.Rules {
		ipfwTableNames = append(ipfwTableNames, rule.Match.TableNames()...)
	}
	return
}

// 独自実装（必要か確認中）
func RulesToRestoreFile(rules []Rule, path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("OpenFile failed: %v", err)
	}
	defer file.Close()

	_, err = file.Write([]byte("#!/bin/sh\n"))
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}

	for _, r := range rules {
		_, err = file.Write([]byte(fmt.Sprintf("%s\n", r.RenderRaw(""))))
		if err != nil {
			return fmt.Errorf("Write Rule(%s) failed: %v", r.Number, err)
		}
	}
	return nil
}

// 独自実装（必要か確認中）
func BytesToRestoreFile(rules []byte, path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("OpenFile failed: %v", err)
	}
	defer file.Close()

	_, err = file.Write([]byte("#!/bin/sh\n"))
	if err != nil {
		return fmt.Errorf("Write shell header failed: %v", err)
	}

	_, err = file.Write(rules)
	if err != nil {
		return fmt.Errorf("Write rules fialed: %v", err)
	}
	return nil
}

// 独自実装
func SetChainNum(chainName string, num uint16) {
	chain, ok := ChainNameToChain[chainName]
	if ok {
		chain.Number = num
	} else {
		newChain := &Chain {
			Name: chainName,
			Number: num,
			Rules: []Rule{},
		}
		ChainNameToChain[chainName] = newChain
	}
}
