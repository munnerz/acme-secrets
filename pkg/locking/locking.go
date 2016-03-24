package locking

import (
	"fmt"
	"sync"
	"time"
)

type Locking struct {
	Provider
}

type Provider interface {
	Lock(lock Interface) (Interface, error)
	Unlock(lock Interface) (Interface, error)
}

type Interface interface {
	GetObject() interface{}
	GetExpiry() time.Time
}

func (l *Locking) LockAll(locks ...Interface) ([]Interface, []error) {
	type result struct {
		lock Interface
		err  error
	}

	lockc := make(chan result, len(locks))
	wg := sync.WaitGroup{}
	wg.Add(len(locks))

	for _, lock := range locks {
		go func(lock Interface) {
			defer wg.Done()
			lock, err := l.Lock(lock)
			lockc <- result{lock, err}
		}(lock)
	}

	wg.Wait()
	close(lockc)

	var createdLocks []Interface
	var errs []error
	for lock := range lockc {
		if lock.err != nil {
			errs = append(errs, lock.err)
			continue
		}
		createdLocks = append(createdLocks, lock.lock)
	}

	if len(errs) > 0 {
		_, unlockErrs := l.UnlockAll(createdLocks...)

		errs = append(errs, unlockErrs...)

		return nil, errs
	}

	return createdLocks, nil
}

func (l *Locking) UnlockAll(locks ...Interface) ([]Interface, []error) {
	var res []Interface
	var errs []error

	for _, lock := range locks {
		if lock, err := l.Unlock(lock); err != nil {
			errs = append(errs, err)
		} else {
			res = append(res, lock)
		}
	}

	return res, nil
}

func New(provider Provider) (*Locking, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider must not be nil")
	}

	return &Locking{
		Provider: provider,
	}, nil
}
