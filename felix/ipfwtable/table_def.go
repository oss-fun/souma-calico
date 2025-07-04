//go:build freebsd

package ipfwtable

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
)

const MaxIpfwTableNameLength = 63

const IpfwTableNamePrefix = "cali"

type IpfwTableType string

const (
	IpfwTableTypeIP    IpfwTableType = "ip"
	IpfwTableTypeNet   IpfwTableType = "net"
	IpfwTableTypeIface IpfwTableType = "iface"
	IpfwTableTypePort  IpfwTableType = "port"
)

var AllIpfwTableTypes = []IpfwTableType{
	IpfwTableTypeIP,
	IpfwTableTypeNet,
	IpfwTableTypeIface,
	IpfwTableTypePort,
}

func (t IpfwTableType) CanonicaliseMenber(member string) IpfwTableMember {
	switch t {
	case IpfwTableTypeIP:
		ipAddr := ip.FromIPOrCIDRString(member)
		if ipAddr == nil {
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case IpfwTableTypeNet:
		return ip.MustParseCIDROrIP(member)
	case IpfwTableTypeIface:
		return rawIpfwTableMember(member)
	case IpfwTableTypePort:
		return rawIpfwTableMember(member)
	}
	log.WithField("type", string(t)).Panic("Unknown TableType")
	return nil
}

type IpfwTableMember interface {
	String() string
}

type rawIpfwTableMember string

func (r rawIpfwTableMember) String() string {
	return string(r)
}

type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

func (f IPFamily) IsValid() bool {
	switch f {
	case IPFamilyV4, IPFamilyV6:
		return true
	}
	return false
}
func (f IPFamily) Version() int {
	switch f {
	case IPFamilyV4:
		return 4
	case IPFamilyV6:
		return 6
	}
	return 0
}

type IpfwTableMetadata struct {
	SetID    string
	Type     IpfwTableType
	MaxSize  int
	RangeMin int
	RangeMax int
}

type IPVersionConfig struct {
	Family                IPFamily
	tableNamePrefix       string
	tempTableNamePrefix   string
	mainTableNamePrefix   string
	ourNamePrefixesRegexp *regexp.Regexp
}

const (
	mainIpfwTableToken = "0"
	tempIpfwTableToken = "t"
)

func NewIPVersionConfig(
	family IPFamily,
	namePrefix string,
	allHistoricPrefixes []string,
	extraUnversionedIPSets []string,
) *IPVersionConfig {
	var version string
	switch family {
	case IPFamilyV4:
		version = "4"
	case IPFamilyV6:
		version = "6"
	}
	versionedPrefix := namePrefix + version
	var versionedPrefixes []string
	versionedPrefixes = append(versionedPrefixes, namePrefix+version)
	for _, prefix := range allHistoricPrefixes {
		versionedPrefixes = append(versionedPrefixes, prefix+version)
	}
	versionedPrefixes = append(versionedPrefixes, extraUnversionedIPSets...)
	for i, pfx := range versionedPrefixes {
		versionedPrefixes[i] = regexp.QuoteMeta(pfx)
	}
	ourNamesPattern := "^(" + strings.Join(versionedPrefixes, "|") + ")"
	log.WithField("regexp", ourNamesPattern).Debug("Calculated IP set name regexp.")
	ourNamesRegexp := regexp.MustCompile(ourNamesPattern)

	return &IPVersionConfig{
		Family:                family,
		tableNamePrefix:       versionedPrefix,
		tempTableNamePrefix:   versionedPrefix + tempIpfwTableToken,
		mainTableNamePrefix:   versionedPrefix + mainIpfwTableToken,
		ourNamePrefixesRegexp: ourNamesRegexp,
	}
}

func (c IPVersionConfig) NameForTempIPSet(n uint) string {
	return fmt.Sprint(c.tempSetNamePrefix, n)
}

func (c IPVersionConfig) NameForMainIPSet(setID string) string {
	return combineAndTrunc(c.mainSetNamePrefix, setID, MaxIPSetNameLength)
}

func (c IPVersionConfig) OwnsIPSet(setName string) bool {
	return c.ourNamePrefixesRegexp.MatchString(setName)
}

func (c IPVersionConfig) IsTempIPSetName(setName string) bool {
	return strings.HasPrefix(setName, c.tempSetNamePrefix)
}

func combineAndTrunc(prefix, suffix string, maxLength int) string {
	combined := prefix + suffix
	if len(combined) > maxLength {
		return combined[0:maxLength]
	} else {
		return combined
	}
}

func StripIPSetNamePrefix(ipSetName string) string {
	prefixLen := len(IPSetNamePrefix) + 2 // "cali40"
	if len(ipSetName) < prefixLen {
		return ""
	}
	return ipSetName[prefixLen:]
}
