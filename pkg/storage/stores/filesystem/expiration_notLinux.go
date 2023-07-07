//go:build !linux

package filesystem

func (s *Store) runGC(gclevel int) error {
	return nil
}
