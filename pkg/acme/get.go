package acme

import (
	"crypto/tls"
	"fmt"

	"github.com/arthurweinmann/go-https-hug/internal/utils"
)

// GetCertificate is for integration into a golang HTTPS server
// Your HTTPS server then searches for existing certificates automatically
func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	d, err := utils.FormatHelloServerName(hello.ServerName)
	if err != nil {
		return nil, fmt.Errorf("FormatHelloServerName: %v", err)
	}

	rootdomain, err := utils.ExtractRootDomain(d)
	if err != nil {
		return nil, fmt.Errorf("ExtractRootDomain: %v", err)
	}

	cert, priv, err := RetrieveCertificate(rootdomain)
	if err != nil {
		return nil, fmt.Errorf("RetrieveCertificate: %v", err)
	}

	// TODO: cache those
	tlscert, err := GenerateCert(cert, priv)
	if err != nil {
		return nil, fmt.Errorf("GenerateCert: %v", err)
	}

	return tlscert, nil
}
