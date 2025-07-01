package ipfwtable

import (
	"fmt"
	"regxp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
)

const MaxTableNameLength = 63

const TableNamePrefix = "cali"

type TableType string

const (
	TableTypeIP    TableType = "ip"
	TableTypeNet   TableType = "net"
	TableTypeIface TableType = "iface"
	TableTypePort  TableType = "port"
)

var AllTableTypes = []TableType{
	TableTypeIP,
	TableTypeNet,
	TableTypeIface,
	TableTypePort,
}

func (t TableType) CanonicaliseMenber(menber string) TableMember {
	switch t {
	case: TableTypeIP:
		ipAddr := ip.FromIPOrCIDRString(member)
		if ipAddr == nil {
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case: TableTypeNet:
		return ip.MustParseCIDROrIP(member)
	case: TableTypeIface:
		return rawTableMember(member)
	case: TableTypePort:
		return rawTableMember(member)
	}
	log.WithField("type", string(t)).Panic("Unknown TableType")
	return nil
}

type TableMember interface {
	String() string
}

type rawTableMember string

func (r rawTableMember) String() string {
	return string(r)
}

type IPVersionConfig struct {
	Family                IPFamily
	tableNamePrefix       string
	temptableNamePrefix   string
	maintableNamePrefix   string
	ourNamePrefixesRegexp *regexp.Regexp
}

const (
	mainTableToken = "0"
	tempTableToken = "t"
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
		TableNamePrefix:       versionedPrefix,
		tempTableNamePrefix:   versionedPrefix + tempIpsetToken,
		mainTableNamePrefix:   versionedPrefix + mainIpsetToken,
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
