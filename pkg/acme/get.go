package acme

import (
	"crypto/tls"
	"fmt"
	"strings"

	"log/slog"

	"github.com/arthurweinmann/go-https-hug/internal/utils"
)

// GetCertificate is for integration into a golang HTTPS server
// Your HTTPS server then searches for existing certificates automatically
func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	logger.Info("GetCertificate", slog.String("helloServerName", hello.ServerName))

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

type whiteListedGetCertificate struct {
	whiteList     map[string]bool
	perRootDomain map[string][]string
}

type WhiteListedGetCertificate = *whiteListedGetCertificate

func NewWhiteListedGetCertificate(whiteList []string) (WhiteListedGetCertificate, error) {
	ret := &whiteListedGetCertificate{
		whiteList:     map[string]bool{},
		perRootDomain: map[string][]string{},
	}
	for _, d := range whiteList {
		ret.whiteList[strings.ToLower(d)] = true
		rootdomain, err := utils.ExtractRootDomain(d)
		if err != nil {
			return nil, err
		}
		ret.perRootDomain[rootdomain] = append(ret.perRootDomain[rootdomain], d)
	}
	return ret, nil
}

func (wlgc WhiteListedGetCertificate) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	logger.Info("GetCertificate", slog.String("helloServerName", hello.ServerName))

	d, err := utils.FormatHelloServerName(hello.ServerName)
	if err != nil {
		logger.Error("error formatting hello servername", slog.String("error", err.Error()))
		return nil, fmt.Errorf("FormatHelloServerName: %v", err)
	}

	rootdomain, err := utils.ExtractRootDomain(d)
	if err != nil {
		logger.Error("error extracting root domain name", slog.String("error", err.Error()))
		return nil, fmt.Errorf("ExtractRootDomain: %v", err)
	}

	cert, priv, err := RetrieveCertificate(rootdomain)
	if err != nil && err != ErrCertificateNotFound && err != ErrCertificateExpired {
		logger.Error("error retrieving certificate", slog.String("error", err.Error()))
		return nil, fmt.Errorf("RetrieveCertificate: %v", err)
	}
	if len(cert) > 0 {
		// TODO: cache those
		tlscert, err := GenerateCert(cert, priv)
		if err != nil {
			logger.Error("error generating certificate", slog.String("error", err.Error()))
			return nil, fmt.Errorf("GenerateCert: %v", err)
		}
		return tlscert, nil
	}

	if !wlgc.whiteList[d] {
		var found bool
		for wd := range wlgc.whiteList {
			if utils.EqualDomain(wd, d) {
				found = true
				break
			}
		}
		if !found {
			logger.Error("unauthorized ssl domain name", slog.String("helloServerName", hello.ServerName))
			return nil, fmt.Errorf("domain %s is not whitelisted for ssl", d)
		}
	}

	cert, priv, err = CreateCertificate(rootdomain, wlgc.perRootDomain[rootdomain], true)
	if err != nil {
		logger.Error("error creating certificate", slog.String("error", err.Error()))
		return nil, fmt.Errorf("ExtractRootDomain: %v", err)
	}

	// TODO: cache those
	tlscert, err := GenerateCert(cert, priv)
	if err != nil {
		logger.Error("error generating certificate", slog.String("error", err.Error()))
		return nil, fmt.Errorf("GenerateCert: %v", err)
	}
	return tlscert, nil
}
