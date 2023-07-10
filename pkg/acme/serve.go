package acme

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/arthurweinmann/go-https-hug/internal/utils"
)

// ServeHTTP starts listening on port 80, if the requested url starts with /.well-known/acme-challenge/
// it will handle the http certificate challenge without calling your handler h, otherwise it hands control over to handler h.
// If handler h is nil, the http server will only handle challenges and send an error for all other requests.
// You may provide an option http server to set its parameters. In this case, only its Handler and Addr fields will be replaced.
func ServeHTTP(h http.Handler, redirectToHTTPS bool, option ...*http.Server) error {
	ch := &challengesResolver{
		redirectToHTTPS: redirectToHTTPS,
		h:               h,
	}

	if h != nil {
		switch h.(type) {
		default:
			ch.hashH = true
		case nil:
		}
	}

	var serv *http.Server
	if len(option) > 0 {
		serv = option[0]
		serv.Addr = ":80"
		serv.Handler = ch
	} else {
		serv = &http.Server{
			Addr:    ":80",
			Handler: ch,

			ReadHeaderTimeout: 30 * time.Second,
			ReadTimeout:       1 * time.Minute,
			WriteTimeout:      1 * time.Minute,
			IdleTimeout:       5 * time.Minute,
		}
	}

	return serv.ListenAndServe()
}

type challengesResolver struct {
	hashH           bool
	h               http.Handler
	redirectToHTTPS bool
}

func (s *challengesResolver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stripedhost := utils.StripPort(r.Host)

	if strings.HasPrefix(r.URL.Path, ACME_CHALLENGE_URL_PREFIX) && len(r.URL.Path) > len(ACME_CHALLENGE_URL_PREFIX) {
		keyauth, err := GetChallenge(stripedhost, r.URL.Path[len(ACME_CHALLENGE_URL_PREFIX):])
		if err != nil {
			logthis(ERROR, "certificates.GetChallenge: %v", err)
			w.WriteHeader(404)
			return
		}

		w.WriteHeader(200)
		w.Write(keyauth)

		logthis(INFO, "served http challenge for: %s", stripedhost)

		return
	}

	logthis(DEBUG, "Received HTTP Request: %s%s", stripedhost, r.URL.Path)

	if !s.hashH {
		if s.redirectToHTTPS {
			utils.Redirect2HTTPS(w, r)
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("We do not support requests in http, please use https"))
		return
	}

	s.h.ServeHTTP(w, r)
}

// Serve is blocking
// Example of addr is :443
// logfilepath is optional and can be empty
func ServeHTTPS(addr string, h http.Handler, logfilepath string) error {
	conn, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := new(tls.Config)
	tlsConfig.GetCertificate = GetCertificate
	tlsListener := tls.NewListener(conn, tlsConfig)

	var f *os.File
	if logfilepath != "" {
		f, err := os.OpenFile("https.log", os.O_CREATE|os.O_RDWR, 0700)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
	}

	serv := &http.Server{
		Addr:    addr,
		Handler: h,

		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       1 * time.Minute,
		WriteTimeout:      1 * time.Minute,
		IdleTimeout:       5 * time.Minute,
	}

	if f != nil {
		serv.ErrorLog = log.New(f, "https: ", log.Llongfile|log.Ltime|log.Ldate)
	}

	fmt.Println("Starting HTTPS Server on", addr)
	return serv.Serve(tlsListener)
}
