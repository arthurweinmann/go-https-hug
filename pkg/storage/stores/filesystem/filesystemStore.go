package filesystem

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arthurweinmann/go-https-hug/pkg/storage"
)

type Store struct {
	directory   string
	lockStore   map[string]bool
	expirations map[string]time.Time
	lsMutex     *sync.Mutex
}

func NewStore(directory string) (*Store, error) {
	out := &Store{
		directory:   directory,
		expirations: map[string]time.Time{},
		lockStore:   map[string]bool{},
		lsMutex:     &sync.Mutex{},
	}

	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return nil, err
	}

	err = out.runGC(gcDefault)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Store) SetKV(key string, value []byte, expiration time.Duration) error {
	p := filepath.Join(s.directory, key)

	err := os.MkdirAll(filepath.Dir(p), 0700)
	if err != nil {
		return err
	}

	_, err = os.Stat(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if err == nil {
		err = os.Remove(p)
		if err != nil {
			return err
		}
	}

	err = os.WriteFile(p, value, 0644)
	if err != nil {
		return err
	}

	if expiration > 0 {
		s.lsMutex.Lock()
		defer s.lsMutex.Unlock()
		s.expirations[p] = time.Now().Add(expiration)
	}

	return err
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

	err = os.Remove(p)
	if err != nil {
		return err
	}

	s.lsMutex.Lock()
	defer s.lsMutex.Unlock()
	delete(s.expirations, p)

	return nil
}

func (s *Store) LockCert(domain string, timeout time.Duration) (bool, error) {
	s.lsMutex.Lock()
	defer s.lsMutex.Unlock()

	if s.lockStore[domain] {
		return false, nil
	}

	s.lockStore[domain] = true
	go func() {
		// TODO: handle the case where UnlockCert is called before the timeout expiring, which is fine
		// but then this goroutine potentially removes the lock from a call that came just after the call to UnlockCert
		// and before the timeout here expired
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
