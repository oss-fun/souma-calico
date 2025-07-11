//go:build freebsd

package tagnum

import (
	"fmt"
	"sync"
)

type TagNumManager struct {
	name    string
	usedNum map[uint16]bool

	mutex   sync.Mutex
}

func NewTagNumManager(tagName string) *TagNumManager {
	return &TagNumManager{name: tagName}
}

func (tm *TagNumManager) NextTagNum() (uint16, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var result uint16
	for ; result <= 65535; result++ {
		if tm.usedNum[result] == true {
			continue
		}
		break
	}

	if result == 0 {
		return 0, fmt.Errorf("NextTagNum Failed")
	}

	if err := tm.SetUsedNum(result); err != nil {
		return 0, err
	}
	return result, nil
}

func (tm *TagNumManager) SetUsedNum(n uint16) error {
	if tm.usedNum[n] == true {
		return fmt.Errorf("SetUsedNum Failed: tag %d already used.", n)
	}

	tm.usedNum[n] = true
	return nil
}
