package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

func FormatHelloServerName(servername string) (string, error) {
	if servername == "" {
		return "", errors.New("missing domain name")
	}

	servername = strings.ToLower(servername)

	servername = strings.Trim(servername, ".") // golang.org/issue/18114

	return servername, nil
}

// ExtractRootDomain extracts the EffectiveTLDPlusOne, see https://godoc.org/golang.org/x/net/publicsuffix#EffectiveTLDPlusOne
// for more explanations
func ExtractRootDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

func VerifyTXT(domain, token string) (bool, error) {
	records, err := GoogleResolver.LookupTXT(context.Background(), domain)
	if err != nil {
		return false, fmt.Errorf("%v: %v", domain, err)
	}

	for i := 0; i < len(records); i++ {
		if records[i] == token {
			return true, nil
		}
	}

	return false, nil
}

func EqualDomain(d1, d2 string) bool {
	// Normalize domains by converting to lowercase
	d1 = strings.ToLower(d1)
	d2 = strings.ToLower(d2)

	// Split domains into parts
	spl1 := strings.Split(d1, ".")
	spl2 := strings.Split(d2, ".")

	// Check if the number of parts is the same
	if len(spl1) != len(spl2) {
		return false
	}

	for i := 0; i < len(spl1); i++ {
		// Check for exact match or wildcard
		if spl1[i] == spl2[i] || spl1[i] == "*" || spl2[i] == "*" {
			continue
		}

		// Check for partial wildcard match
		if strings.Contains(spl1[i], "*") {
			if !wildcardMatch(spl1[i], spl2[i]) {
				return false
			}
		} else if strings.Contains(spl2[i], "*") {
			if !wildcardMatch(spl2[i], spl1[i]) {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

func wildcardMatch(pattern, str string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == str
	}

	if !strings.HasPrefix(str, parts[0]) {
		return false
	}

	str = str[utf8.RuneCountInString(parts[0]):]

	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(str, parts[i])
		if idx == -1 {
			return false
		}
		str = str[idx+utf8.RuneCountInString(parts[i]):]
	}

	return strings.HasSuffix(str, parts[len(parts)-1])
}
