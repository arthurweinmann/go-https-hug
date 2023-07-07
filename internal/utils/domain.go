package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func FormatHelloServerName(servername string) (string, error) {
	if servername == "" {
		return "", errors.New("missing domain name")
	}

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
	spl1 := strings.Split(d1, ".")
	spl2 := strings.Split(d2, ".")

	if len(spl1) != len(spl2) {
		return false
	}

	for i := 0; i < len(spl1); i++ {
		if spl1[i] != spl2[i] && spl1[i] != "*" && spl2[i] != "*" {
			return false
		}
	}

	return true
}
