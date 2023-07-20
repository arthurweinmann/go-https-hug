package acme

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arthurweinmann/go-https-hug/internal/utils"
	"github.com/arthurweinmann/go-https-hug/pkg/storage"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

var ErrCertificateNotFound = errors.New("certificate not found")
var ErrCertificateExpired = errors.New("certificate expired")

var legoconfig *lego.Config
var client *lego.Client
var reg *registration.Resource
var createMu sync.RWMutex
var httpChal *HTTPChallenger

func createHandler(us *ACMEUser, isnew bool) error {
	var err error

	legoconfig = lego.NewConfig(us)
	legoconfig.CADirURL = lego.LEDirectoryProduction

	client, err = lego.NewClient(legoconfig)
	if err != nil {
		return err
	}

	httpChal = &HTTPChallenger{}
	err = client.Challenge.SetHTTP01Provider(httpChal)
	if err != nil {
		return err
	}

	if settings.DNSProvider != nil {
		dchal, err := newDNSChallenger(settings.DNSProvider)
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(dchal)
		if err != nil {
			return err
		}
	}

	if isnew {
		// New users will need to register
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		us.Registration = reg

		err = us.Save()
		if err != nil {
			return err
		}
	} else {
		// check registration
		reg, err = client.Registration.QueryRegistration()
		if err != nil {
			return err
		}
	}

	return nil
}

func CreateCertificate(rootdomain string, domains []string, lock bool) ([]byte, []byte, error) {
	var certificates *certificate.Resource
	var err error

	if lock {
		ok, err := settings.Store.LockCert(rootdomain, 5*time.Minute)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, nil
		}
		defer settings.Store.UnlockCert(rootdomain)
	}

	certificates, err = client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, nil, err
	}

	err = storeCertificate(rootdomain, domains, certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return certificates.Certificate, certificates.PrivateKey, nil
}

func getCertificate(domain string) (*tls.Certificate, error) {
	cert, priv, err := RetrieveCertificate(domain)
	if err != nil {
		switch err {
		case ErrCertificateNotFound, ErrCertificateExpired:
		default:
			return nil, fmt.Errorf("RetrieveCertificate: %v", err)
		}

		rootdomain, err := utils.ExtractRootDomain(domain)
		if err != nil {
			return nil, err
		}
		rootdomain = strings.ToLower(rootdomain)

		var domains []string

		authd, ok := settings.AuthorizedDomains[rootdomain]
		if !ok {
			return nil, fmt.Errorf("The root domain %s is not authorized", domain)
		}

		domains = append(domains, rootdomain)
		for d, a := range authd {
			if a {
				domains = append(domains, d)
			}
		}

		cert, priv, err = CreateCertificate(rootdomain, domains, true)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, nil
		}
	}

	return GenerateCert(cert, priv)
}

func ToggleCertificate(domains []string) error {
	rootdomain, err := utils.ExtractRootDomain(domains[0])
	if err != nil {
		return err
	}

	_, _, err = RetrieveCertificate(rootdomain)
	if err != nil {
		if err != ErrCertificateExpired && err != ErrCertificateNotFound {
			return err
		}

		_, _, err = CreateCertificate(rootdomain, domains, true)
		if err != nil {
			return err
		}
	}

	return nil
}

// TODO: store the list of subdomains too in order to recreate the cert if this list has changed
func storeCertificate(rootdomain string, domains []string, certificate, privateKey []byte) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(struct {
		Deadline    int64
		RootDomain  string
		Domains     []string
		Certificate []byte
		PrivateKey  []byte
	}{
		Deadline:    time.Now().Add(744 * time.Hour).Unix(), // renew in a month do not wait the 3
		RootDomain:  rootdomain,
		Domains:     domains,
		Certificate: certificate,
		PrivateKey:  privateKey,
	})
	if err != nil {
		return err
	}

	b := buf.Bytes()

	err = settings.Store.SetKV("certificates/"+rootdomain, b, 0)
	if err != nil {
		return err
	}

	if cache != nil {
		cache.Set([]byte(rootdomain), b)
	}

	return nil
}

func RetrieveCertificate(domain string) (certificate, privateKey []byte, err error) {
	var b []byte

	if cache != nil {
		b = cache.Get(nil, []byte(domain))
	}

	if len(b) == 0 {
		b, err = settings.Store.GetKV("certificates/" + domain)
		if err != nil {
			if err == storage.ErrNotFound {
				err = ErrCertificateNotFound
			}
			return
		}

		if cache != nil {
			cache.Set([]byte(domain), b)
		}
	}

	dec := gob.NewDecoder(bytes.NewReader(b))

	var q struct {
		Deadline    int64
		RootDomain  string
		Domains     []string
		Certificate []byte
		PrivateKey  []byte
	}
	err = dec.Decode(&q)
	if err != nil {
		return nil, nil, err
	}

	deadline := time.Unix(q.Deadline, 0)
	now := time.Now()

	if now.After(deadline) {
		go func() {
			ok, err := settings.Store.LockCert(q.RootDomain+"##@@##renewal", 5*time.Minute)
			if err != nil {
				fmt.Println("Could not lock certificate for renewal:", q.RootDomain, err)
				return
			}
			if !ok {
				// another goroutine is already renewing
				return
			}
			defer settings.Store.UnlockCert(q.RootDomain + "##@@##renewal")

			_, _, err = CreateCertificate(q.RootDomain, q.Domains, true)
			if err != nil {
				fmt.Println("Could not renew certificate:", q.RootDomain, err)
				return
			}
		}()

		// Let's encrypt certificates are good for 3 months
		if now.Sub(deadline) > 1116*time.Hour {
			return nil, nil, ErrCertificateExpired
		}
	}

	certificate = q.Certificate
	privateKey = q.PrivateKey

	return
}

func GenerateCert(certificate []byte, privateKey []byte) (*tls.Certificate, error) {
	// Leaf is nil when using this method, see if we need to provide id
	// See https://stackoverflow.com/questions/43605755/whats-the-leaf-certificate-and-sub-certificate-used-for-and-how-to-use-them
	cert, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
