package storage

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	// key may contain / and ., for example user/account.json
	SetKV(key string, value []byte, expiration time.Duration) error

	GetKV(key string) ([]byte, error)

	DeleteKV(key string) error

	LockCert(domain string, timeout time.Duration) (bool, error)
	UnlockCert(domain string) error
}
