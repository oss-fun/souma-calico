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
	if _, isCheckState := r.Action.(CheckStateAction); isCheckState {
		// check-state は条件部分を持たない。ipfw(8) と sbin/ipfw/ipfw2.c の compile_rule() は、
		// check-state の直後のコメント（// …）だけを受け付けて残りを読まないため、
		// 条件部分を付けるとハッシュのコメントが付かなくなる。
	} else {
		matchFragment := r.Match.Render()
		if matchFragment != "" {
			fragments = append(fragments, matchFragment)
		} else {
			allPacketMatch := Match().SourceNet("any").DestNet("any").Render()
			fragments = append(fragments, allPacketMatch)
		}
	}
	if comment := renderComment(r.Comment, prefixFragment); comment != "" {
		fragments = append(fragments, comment)
	}
	return strings.Join(fragments, " ")
}

// MaxIpfwCommentLen は、ipfw のコメント（最初の "//" より後ろ）の最大の長さ。
// sbin/ipfw/ipfw2.c の fill_comment() は、"//" より後ろの各語の長さ+1 の合計が 84 を超えると
// "comment too long (max 80 chars)" で失敗する。余裕を見て 80 文字にする。
const MaxIpfwCommentLen = 80

// renderComment は、説明のコメント（comments）とハッシュのコメント（prefixFragment、"// cali:..."）を
// つないだコメント部分を返す。形は "// 説明1 // 説明2 // cali:..."。
//
//   - ルールは sh のスクリプトとして実行する（execIpfwRestore / RulesToRestoreFile）ため、
//     説明に ; や引用符などがあるとシェルに解釈される（; ならそこでコマンドが分かれ、残りが別の
//     コマンドとして実行される）。シェルで安全な文字以外は _ に置き換える。
//   - 長さが MaxIpfwCommentLen を超えると ipfw add が失敗する。ハッシュのコメントは読み直しに
//     必要なので必ず残し、説明の側を切り詰める（入りきらなければ説明を省く）。
func renderComment(comments []string, prefixFragment string) string {
	escaped := make([]string, 0, len(comments))
	for _, c := range comments {
		if c = strings.TrimSpace(escapeComment(c)); c != "" {
			escaped = append(escaped, c)
		}
	}
	description := strings.Join(escaped, " // ")
	hash := strings.TrimPrefix(prefixFragment, "// ")

	// 説明に使える長さ（ハッシュがあるときは " // " とハッシュの分を除く）
	available := MaxIpfwCommentLen
	if hash != "" {
		available -= len(" // ") + len(hash)
	}
	if len(description) > available {
		if available > 0 {
			description = strings.TrimSpace(description[:available])
		} else {
			description = ""
		}
	}

	switch {
	case description != "" && hash != "":
		return "// " + description + " // " + hash
	case description != "":
		return "// " + description
	case hash != "":
		return "// " + hash
	default:
		return ""
	}
}

// shellUnsafe は、コメントに残すとシェルに解釈される文字（許可する文字以外）に一致する。
// # は語の先頭にあるとシェルのコメントになり、それ以降（ハッシュのコメントを含む）が捨てられる。
// コマンド自体は成功するため set -e でも検出できず、ハッシュのないルールが管理対象から漏れる。
// そのため # も許可しない。
var shellUnsafe = regexp.MustCompile(`[^\w @%+=:,./-]`)

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
	if c.Number != 0 {
		return c.Number
	}

	chain, ok := ChainNameToChain[c.Name]
	if ok {
		if chain.Number != 0 {
			c.Number = chain.Number
			return c.Number
		}
	}
	//case len(c.Rules) != 0:
	//	c.Number = c.Rules[0].Number
	//	return c.Number
	
	return 65535
}

// chain番号とかルール番号の成形
func (c *Chain) Organize() error {
	if c == nil {
		return fmt.Errorf("Chain is nill")
	}

	// 本体のルール数の検査。区画は「開始番号: count」「開始番号+1〜+N: 本体」
	// 「開始番号+RULE_BUF-1: return」なので、本体は MaxChainBodyRules 個まで。
	// 超えると末尾の return と同じ番号になるか、次のチェインの区画に入り込む。
	if len(c.Rules) > MaxChainBodyRules {
		return fmt.Errorf("chain %s has %d rules, but at most %d rules fit in a %d-number block",
			c.Name, len(c.Rules), MaxChainBodyRules, RULE_BUF)
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
	// 区画全体（開始番号〜開始番号+RULE_BUF-1）が使える番号に収まることを確認する。
	if int(start)+RULE_BUF-1 > MaxChainRuleNumber {
		return fmt.Errorf("chain %s block %d-%d exceeds the maximum rule number %d",
			c.Name, start, int(start)+RULE_BUF-1, MaxChainRuleNumber)
	}
	c.Number = start

	createChainRule := []Rule {
		{
			Action: CountAction{},
		},
	}
	c.Rules = append(createChainRule, c.Rules...)

	// rule番号の生成
	for i, _ := range c.Rules {
		c.Rules[i].Number = c.Number + uint16(i)
	}

	endRule := Rule {
		Number: c.Number + RULE_BUF -1,
		Action: ReturnAction{},
	}
	c.Rules = append(c.Rules, endRule)
	
	_, ok := ChainNameToChain[c.Name]
	if !ok {
		ChainNameToChain[c.Name] = c
	}

	return nil
}

const (
	// 1つのチェインに割り当てる番号の区画の大きさ。
	RULE_BUF = 100

	// チェインに使える最大のルール番号。
	// 65534 は各区画の終わりの skipto 先（END_RULE）、65535 は IPFW の既定ルールのため使わない。
	MaxChainRuleNumber = 65533

	// 1つのチェインの本体に置けるルール数（先頭の count と末尾の return を除く）。
	MaxChainBodyRules = RULE_BUF - 2
)

// 呼び出しの深さについて:
// IPFW の call の呼び出し履歴は 16 段まで（ipfw(8): "currently has size of 16 entries"）。
// 上限に達した状態の call は、呼び出し先へ移らずに次のルールへ進む（ip_fw2.c O_CALLRETURN）。
// 現在の構成での最大の深さは、振り分け(1) → 段階のチェイン(2) → dispatch / host endpoint dispatch(3)
// → エンドポイントのチェイン（skipto のため増えない）→ ポリシーグループ(4) → ポリシー(5) で、16 段未満。
// チェインの入れ子を増やす場合は、この深さを確認すること。

// chain番号の生成
//
// 既存のチェインの最大の開始番号 + RULE_BUF を新しい開始番号にする。
// uint16 で計算すると上限を超えたときに低い番号へ折り返すため、int で計算し、
// 区画全体（開始番号〜開始番号+RULE_BUF-1）が MaxChainRuleNumber に収まることを確認する。
func SetNewNumber() (uint16, error) {
	max := 0
	for _, c := range ChainNameToChain {
		if n := int(c.Number); n > max {
			max = n
		}
	}
	next := max + RULE_BUF
	if next+RULE_BUF-1 > MaxChainRuleNumber {
		return 0, fmt.Errorf("no chain number block left: next block %d-%d exceeds %d",
			next, next+RULE_BUF-1, MaxChainRuleNumber)
	}

	return uint16(next), nil
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

	_, err = file.Write([]byte(RestoreScriptHeader))
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}

	for _, r := range rules {
		_, err = file.Write([]byte(fmt.Sprintf("%s\n", r.RenderRaw(""))))
		if err != nil {
			return fmt.Errorf("Write Rule(%d) failed: %v", r.Number, err)
		}
	}
	return nil
}

// RestoreScriptHeader はルールを反映するスクリプトの先頭。
// set -e により、ipfw のコマンドが失敗した行でスクリプトを止め、0 以外で終了させる。
// 以前は最後のコマンドの終了状態だけが返り、途中のルール（deny など）の追加に失敗しても
// 成功として扱われ、キャッシュも成功した状態に更新されていた。
// 失敗してよいコマンド（存在しないかもしれない番号の削除など）は、行の側で明示的に失敗を許す。
const RestoreScriptHeader = "#!/bin/sh\nset -e\n"

// 独自実装（必要か確認中）
func BytesToRestoreFile(rules []byte, path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("OpenFile failed: %v", err)
	}
	defer file.Close()

	_, err = file.Write([]byte(RestoreScriptHeader))
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
		if err := newChain.Organize(); err != nil {
			log.WithField("err", err).Panicf("Failed SetChainNum newChain Organize: %s", chainName)
		}
		ChainNameToChain[chainName] = newChain
	}
}
