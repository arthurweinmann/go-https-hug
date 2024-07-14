//go:build !linux

package filesystem

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

type codeFile struct {
	fname   string
	lastmod int64
}

func (s *Store) runGC(gclevel int) error {
	switch gclevel {
	case gcSkip:
		defer time.AfterFunc(time.Minute*10, s.gc)
	case gcDefault:
		defer time.AfterFunc(time.Minute*5, s.gc)
	case gcClean:
		defer time.AfterFunc(time.Minute*2, s.gc)
	case gcHard:
		defer time.AfterFunc(time.Second*15, s.gc)
	}

	fileArr := make([]*codeFile, 0)
	err := filepath.Walk(s.directory, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			f, err := os.Stat(path)
			if err != nil {
				return err
			}
			statT, ok := f.Sys().(*unix.Stat_t)
			if !ok {
				return fmt.Errorf("received invalid datatype from f.Sys()")
			}
			atim := statT.Atim.Sec
			fileArr = append(fileArr, &codeFile{
				fname:   path,
				lastmod: atim,
			})
		}

		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(fileArr, func(i, j int) bool { return fileArr[i].lastmod < fileArr[j].lastmod })

	for _, v := range fileArr {
		s.lsMutex.Lock()
		deadline, ok := s.expirations[v.fname]
		s.lsMutex.Unlock()

		if ok && time.Now().After(deadline) {
			err := os.Remove(v.fname)
			if err != nil {
				return err
			}

			s.lsMutex.Lock()
			delete(s.expirations, v.fname)
			s.lsMutex.Unlock()
		}
	}

	return nil
}

func (s *Store) gc() {
	all, free, _, err := DiskUsage(s.directory)
	if err != nil {
		fmt.Println("Error getting disk usage:", err)
		s.runGC(gcDefault)
		return
	}

	if all == 0 {
		s.runGC(gcDefault)
		return
	}

	used := 1 - (float64(free) / float64(all))

	switch {
	case used < 0.2:
		s.runGC(gcSkip)
	case used < 0.6:
		s.runGC(gcDefault)
	case used < 0.8:
		s.runGC(gcClean)
	default:
		s.runGC(gcHard)
	}
}

func DiskUsage(path string) (all, free, used uint64, err error) {
	var fs unix.Statfs_t
	err = unix.Statfs(path, &fs)
	if err != nil {
		return
	}
	all = fs.Blocks * uint64(fs.Bsize)
	free = fs.Bfree * uint64(fs.Bsize)
	used = all - free
	return
}
