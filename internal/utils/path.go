package utils

import "strings"

func ContainsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, IsSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func IsSlashRune(r rune) bool { return r == '/' || r == '\\' }
