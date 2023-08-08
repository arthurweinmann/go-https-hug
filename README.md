# Golang Seamless HTTPS

You may feel the urge to hug it.

# How to use

## Example

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/username/blog/internal/config"
	"github.com/arthurweinmann/go-https-hug/pkg/acme"
	"github.com/arthurweinmann/go-https-hug/pkg/router"
	"github.com/arthurweinmann/go-https-hug/pkg/storage/stores/filesystem"
)

func main() {
	boolArgs, stringargs := parseArgs()

	for argname := range boolArgs {
		if argname == "help" {
			fmt.Println(`You may use:
			--home to set the home directory
			--webdomain to set the domain serving the public website
			--contactemail to set the contact email for the creation of Let's Encrypt certificates
			`)
			return
		}
		log.Fatalf("unrecognized bool argument %s", argname)
	}

	for argname, argval := range stringargs {
		switch argname {
		case "home":
			config.HOME = argval
		case "webdomain":
			config.PublicWebsiteDomain = argval
		case "contactemail":
			config.CertificateContactEmail = argval
		default:
			log.Fatalf("unrecognized string argument %s", argname)
		}
	}

	// Check if all mandatory arguments are present
	if config.HOME == "" || config.PublicWebsiteDomain == "" || config.CertificateContactEmail == "" {
		log.Fatal("command line arguments --home, --contactemail and --webdomain are mandatory")
	}

	// Setting up router
	router, err := router.NewRouter(&router.RouterConfig{
		ServeHTMLFolder:       filepath.Join(config.HOME, "web"),
		HTMLFolderDomainNames: []string{"example.com", "www.example.com"},
		RedirectHTTP2HTTPS:    true,
		OnlyHTTPS:             true,
		PerDomain:             map[string]func(r *router.Router, spath []string, w http.ResponseWriter, req *http.Request){},
	})
	if err != nil {
		log.Fatalf("Failed to set up router: %v", err)
	}

	// Setting up filesystem store
	store, err := filesystem.NewStore(filepath.Join(config.HOME, "storage"))
	if err != nil {
		log.Fatalf("Failed to set up filesystem store: %v", err)
	}

	// Initializing ACME
	err = acme.Init(&acme.InitParameters{
		InMemoryCacheSize:       32 * 1024 * 1024,
		CertificateContactEmail: config.CertificateContactEmail,
		Store:                   store,
		AuthorizedDomains: map[string]map[string]bool{
			config.PublicWebsiteDomain: {
				"www." + config.PublicWebsiteDomain: true,
			},
		},
		DNSProvider: nil,
		LogLevel:    acme.DEBUG,
		Logger:      os.Stdout,
	})
	if err != nil {
		log.Fatalf("Failed to initialize ACME: %v", err)
	}

	go acme.ServeHTTP(nil, true)

	err = acme.ToggleCertificate([]string{config.PublicWebsiteDomain, "www." + config.PublicWebsiteDomain})
	if err != nil {
		log.Fatalf("Failed to toggle certificate: %v", err)
	}

	err = acme.ServeHTTPS(":443", router, filepath.Join(config.HOME, "https.log"))
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to serve HTTPS: %v", err)
	}
}

func parseArgs() (map[string]bool, map[string]string) {
	boolArgs := make(map[string]bool)
	strArgs := make(map[string]string)

	// Parsing command line arguments
	for i := 1; i < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "--") {
			arg := strings.TrimPrefix(os.Args[i], "--")
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				strArgs[arg] = os.Args[i+1]
				i++ // skip next arg
			} else {
				boolArgs[arg] = true
			}
		}
	}

	return boolArgs, strArgs
}
```