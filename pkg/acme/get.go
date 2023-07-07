package acme

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

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

func ExampleGetCertificate() {
	conn, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := new(tls.Config)
	tlsConfig.GetCertificate = GetCertificate
	tlsListener := tls.NewListener(conn, tlsConfig)

	f, err := os.OpenFile("https.log", os.O_CREATE|os.O_RDWR, 0700)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	serv := &http.Server{
		Addr:     ":443",
		Handler:  http.NewServeMux(),
		ErrorLog: log.New(f, "https: ", log.Llongfile|log.Ltime|log.Ldate),

		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       1 * time.Minute,
		WriteTimeout:      1 * time.Minute,
		IdleTimeout:       5 * time.Minute,
	}

	fmt.Println("Starting HTTPS Server")
	serv.Serve(tlsListener)

	// Output:
	// Starting HTTPS Server
}
