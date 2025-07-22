// Copyright (c) 2020 Tigera, Inc. All rights reserved.
// Copyright 2017 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is based on that extracted from Kubernetes at pkg/util/ipfw/ipfw_linux.go.

//go:build freebsd

package ipfw

import (
	"errors"
	"fmt"
	"os"
	"time"

	"io"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

var (
	summaryLockAcquisitionTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_ipfw_lock_acquire_secs",
		Help: "Time in seconds that it took to acquire the ipfw lock(s).",
	})
	countLockRetries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_lock_retries",
		Help: "Number of times the ipfw lock was held by someone else and we had to retry.",
	})
)

func init() {
	prometheus.MustRegister(
		summaryLockAcquisitionTime,
		countLockRetries,
	)
}

func NewSharedLock(lockFilePath string, lockTimeout, lockProbeInterval time.Duration) *SharedLock {
	return &SharedLock{
		lockFilePath:      lockFilePath,
		lockTimeout:       lockTimeout,
		lockProbeInterval: lockProbeInterval,
		GrabIpfwLocks:     GrabIpfwLocks,
	}
}

// SharedLock allows for multiple goroutines to share the ipfw lock without blocking on each
// other.  That is safe because each of our goroutines is accessing a different ipfw table, so
// they do not conflict.
type SharedLock struct {
	lock           sync.Mutex
	referenceCount int

	ipfwLockHandle io.Closer

	lockFilePath      string
	lockTimeout       time.Duration
	lockProbeInterval time.Duration

	GrabIpfwLocks func(lockFilePath, socketName string, timeout, probeInterval time.Duration) (io.Closer, error)
}

func (l *SharedLock) Lock() {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.referenceCount == 0 {
		// The lock isn't currently held.  Acquire it.
		lockHandle, err := l.GrabIpfwLocks(
			l.lockFilePath,
			"@ipfw",
			l.lockTimeout,
			l.lockProbeInterval,
		)
		if err != nil {
			// We give the lock plenty of time so err on the side of assuming a
			// programming bug.
			log.WithError(err).Panic("Failed to acquire ipfw lock")
		}
		l.ipfwLockHandle = lockHandle
	}
	l.referenceCount++
}

func (l *SharedLock) Unlock() {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.referenceCount--
	if l.referenceCount < 0 {
		log.Panic("Unmatched Unlock()")
	}
	if l.referenceCount == 0 {
		log.Debug("Releasing ipfw lock.")
		err := l.ipfwLockHandle.Close()
		if err != nil {
			// We haven't done anything with the file or socket so we shouldn't be
			// able to hit any "deferred flush" type errors from the close.  Panic
			// since we're not sure what's going on.
			log.WithError(err).Panic("Error while closing ipfw lock.")
		}
		l.ipfwLockHandle = nil
	}
}

type Locker struct {
	Lock16 io.Closer
	Lock14 io.Closer
}

func (l *Locker) Close() error {
	var err error
	if l.Lock16 != nil {
		err = l.Lock16.Close()
		if err != nil {
			log.WithError(err).Error("Error while closing lock file.")
		}
	}
	if l.Lock14 != nil {
		err14 := l.Lock14.Close()
		if err14 != nil {
			log.WithError(err14).Error("Error while closing lock socket.")
		}
		if err14 != nil && err == nil {
			err = err14
		}
	}
	return err
}

var (
	ErrLockTimeout = errors.New("Timed out waiting for ipfw lock")
)

func GrabIpfwLocks(lockFilePath, socketName string, timeout, probeInterval time.Duration) (io.Closer, error) {
	var err error
	var success bool

	l := &Locker{}
	defer func(l *Locker) {
		// Clean up immediately on failure
		if !success {
			l.Close()
		}
	}(l)

	f, err := os.OpenFile(lockFilePath, os.O_CREATE, 0600)
	l.Lock16 = f
	if err != nil {
		return nil, fmt.Errorf("failed to open ipfw lock %s: %v", lockFilePath, err)
	}

	startTime := time.Now()
	for {
		if err := grabIpfwFileLock(f); err == nil {
			break
		}
		if time.Since(startTime) > timeout {
			return nil, ErrLockTimeout
		}
		time.Sleep(probeInterval)
		countLockRetries.Inc()
	}

	summaryLockAcquisitionTime.Observe(time.Since(startTime).Seconds())

	success = true
	return l, nil
}

func grabIpfwFileLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
