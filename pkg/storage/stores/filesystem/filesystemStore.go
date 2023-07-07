package filesystem

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arthurweinmann/go-https-hug/pkg/storage"
)

type Store struct {
	directory string
	lockStore map[string]bool
	lsMutex   *sync.Mutex
}

func NewStore(directory string) (*Store, error) {
	out := &Store{
		directory: directory,
		lockStore: map[string]bool{},
		lsMutex:   &sync.Mutex{},
	}

	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Store) SetKV(key string, value []byte, expiration time.Duration) error {
	p := filepath.Join(s.directory, key)

	_, err := os.Stat(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if err == nil {
		err = os.Remove(p)
		if err != nil {
			return err
		}
	}

	return os.WriteFile(p, value, 0644)
}

func (s *Store) GetKV(key string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.directory, key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

func (s *Store) DeleteKV(key string) error {
	p := filepath.Join(s.directory, key)

	_, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.ErrNotFound
		}
		return err
	}

	return os.Remove(p)
}

func (s *Store) LockCert(domain string, timeout time.Duration) (bool, error) {
	s.lsMutex.Lock()
	defer s.lsMutex.Unlock()

	if s.lockStore[domain] {
		return false, nil
	}

	s.lockStore[domain] = true
	go func() {
		time.Sleep(timeout)
		s.lsMutex.Lock()
		defer s.lsMutex.Unlock()
		delete(s.lockStore, domain)
	}()

	return true, nil
}

func (s *Store) UnlockCert(domain string) error {
	s.lsMutex.Lock()
	defer s.lsMutex.Unlock()
	delete(s.lockStore, domain)
	return nil
}
