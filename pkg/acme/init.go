package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/mail"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/arthurweinmann/go-https-hug/pkg/storage"
	"github.com/go-acme/lego/v4/challenge"
)

var cache *fastcache.Cache
var settings *InitParameters

type InitParameters struct {
	// if zero, then we do not initialize any cache
	// otherwise the size in bytes of the in memory certificates cache.
	// If InMemoryCacheSize is less than 32MB, then the minimum cache capacity is 32MB.
	InMemoryCacheSize int

	CertificateContactEmail string

	Store storage.Store

	// you may use one of the providers from github.com/go-acme/lego/v4/providers/dns
	// for example route53.NewDNSProviderConfig
	DNSProvider   challenge.Provider
	DNSChallenges bool

	// Each main map key correspond to a root domain name, e.g. example.com
	// Each sub map key correspond to a subdomain of the parent root domain, e.g. bob.example.com or *.example.com
	// Please note that the use of the wildcard operator * is only possible when you define a DNS provider for your domains
	AuthorizedDomains map[string]map[string]bool

	LogLevel LogLevel
	Logger   io.Writer
}

// Call Init before calling any other function
func Init(param *InitParameters) error {
	if param == nil {
		return fmt.Errorf("We need a non nil *InitParameters argument")
	}

	settings = param

	switch settings.Store.(type) {
	case nil:
		return fmt.Errorf("We need a Store in the parameters")
	}

	if settings.LogLevel != NONE {
		switch settings.Logger.(type) {
		case nil:
			return fmt.Errorf("We need a Logger in the parameters when the LogLevel is different from NONE")
		}
	}

	if settings.InMemoryCacheSize > 0 {
		cache = fastcache.New(settings.InMemoryCacheSize)
	}

	if settings.CertificateContactEmail == "" {
		return fmt.Errorf("We need a certificate contact email in the parameters")
	}

	_, err := mail.ParseAddress(settings.CertificateContactEmail)
	if err != nil {
		return fmt.Errorf("invalid certificate contact email address: %v", err)
	}

	if len(settings.AuthorizedDomains) == 0 {
		return fmt.Errorf("We need at least one authorized root domain name")
	}

	us, err := loadACMEUserFromDisk()
	if err != nil && err != storage.ErrNotFound {
		return err
	}

	if err == storage.ErrNotFound {
		// Create a user. New accounts need an email and private key to start.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		us = &ACMEUser{
			Email: settings.CertificateContactEmail,
			key:   privateKey,
		}

		err = createHandler(us, true)
		if err != nil {
			return err
		}

		return nil
	}

	err = createHandler(us, false)
	if err != nil {
		return err
	}

	return nil
}
