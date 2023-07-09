package acme

import (
	"crypto/tls"
	"encoding/binary"
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

	err = storeCertificate(rootdomain, certificates.Certificate, certificates.PrivateKey)
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
func storeCertificate(domain string, certificate, privateKey []byte) error {
	b := make([]byte, 10, len(certificate)+len(privateKey)+10)

	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().Add(744*time.Hour).Unix()))
	binary.BigEndian.PutUint16(b[8:], uint16(len(certificate)))

	b = append(b, certificate...)
	b = append(b, privateKey...)

	err := settings.Store.SetKV("certificates/"+domain, b, 0)
	if err != nil {
		return err
	}

	if cache != nil {
		cache.Set([]byte(domain), b)
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

	if uint64(time.Now().Unix()) > binary.BigEndian.Uint64(b[:8]) {
		return nil, nil, ErrCertificateExpired
	}

	lc := binary.BigEndian.Uint16(b[8:])
	certificate = b[10 : lc+10]
	privateKey = b[lc+10:]

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
