//go:build freebsd

package tagnum

import (
	"fmt"
	"sync"

	"golang.org/x/exp/slices"
)

type TagNumManager struct {
	name    string
	UsedNum []uint16

	mutex   sync.Mutex
}

func NewTagNumManager(tagName string) *TagNumManager {
	return &TagNumManager{name: tagName}
}

func (mc *TagNumManager) NextTagNum() (uint16, error) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	var result uint16
	for i := 1; i <= 65535; i++ {
		if slices.Contains(mc.UsedNum, uint16(i)) {
			continue
		}
		result = uint16(i)
		break
	}

	if result == 0 {
		return 0, fmt.Errorf("NextTagNum Failed")
	}

	mc.UsedNum = append(mc.UsedNum, result)
	return result, nil
}

