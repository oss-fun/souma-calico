//go:build freebsd

package ipfw

import (
	"fmt"
	"os"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"strconv"

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
	return r.renderInner(fragments, prefixFragment)
}

func (r Rule) RenderAppend(chain Chain, prefixFragment string) string {
	fragments := []string{}
	ruleNum := strconv.Itoa(int(chain.GetStartRuleNum()))
	fragments = append(fragments, append(cmdshim.ADD_COMMAND, ruleNum)...)
	return r.renderInner(fragments, prefixFragment)
}

func (r Rule) renderInner(fragments []string, prefixFragment string) string {
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
	if prefixFragment != "" {
		fragments = append(fragments, prefixFragment)
	}
	if len(r.Comment) > 0 {
		for _, c := range r.Comment {
			fmt.Printf("[Souma-log] Comment: %s\n",c)
			fragments = append(fragments, fmt.Sprintf("// %s", c))
		}
	}
	return strings.Join(fragments, " ")
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
		ruleForHashing := rule.RenderAppend(*c, "HASH")
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
	case len(c.Rules) != 0:
		c.Number = c.Rules[0].Number
		return c.Number
	case ChainNameToChainNum[c.Name] != 0:
		c.Number = ChainNameToChainNum[c.Name]
		return c.Number
	default:
		// log.Panic("GetStartRuleNum failed: no number found for chain ", c.Name)
		return 0
	}
}

// chain番号とかルール番号の成形
func (c *Chain) Organize() error {
	if c == nil {
		return fmt.Errorf("Chain is nill")
	}

	// chain番号の生成
	start := c.GetStartRuleNum()
	if start == 0 {
		n, err := c.SetNewNumber()
		start = n
		if err != nil {
			return fmt.Errorf("SetNewNumber failed: %v", err)
		}
	}
	ChainNameToChainNum[c.Name] = start

	// rule番号の生成
	for i, r := range c.Rules {
		r.Number = start + uint16(i)
	}

	return nil
}

const (
	RULE_BUF = 10
)

// chain番号の生成
func (c *Chain) SetNewNumber() (uint16, error) {
	var result uint16
	for _, n := range ChainNameToChainNum {
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

func (c *Chain) IpfwTableNames() (ipfwTableNames []string) {
	if c == nil {
		return nil
	}
	for _, rule := range c.Rules {
		ipfwTableNames = append(ipfwTableNames, rule.Match.TableNames()...)
	}
	return
}

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

