package acme

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

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
