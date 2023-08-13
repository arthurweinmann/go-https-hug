package router

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/arthurweinmann/go-https-hug/internal/utils"
	"github.com/arthurweinmann/go-https-hug/pkg/acme"
)

type Router struct {
	State any

	serveHTMLFolder       string
	htmlFolderDomainNames []string
	redirectHTTP2HTTPS    bool
	perDomainHijack       map[string][]func(r *Router, spath []string, w http.ResponseWriter, req *http.Request, domain string) bool
	onlyHTTPS             bool
	allowedHeaders        string
}

type RouterConfig struct {
	// any struct or map you may need
	State any

	// folder path
	ServeHTMLFolder       string
	HTMLFolderDomainNames []string

	PageViewsPath string

	RedirectHTTP2HTTPS bool
	OnlyHTTPS          bool

	PerDomainHijack map[string][]func(r *Router, spath []string, w http.ResponseWriter, req *http.Request, domain string) bool

	AllowCustomHeaders []string
}

func NewRouter(config *RouterConfig) (*Router, error) {
	if (config.ServeHTMLFolder != "" || config.HTMLFolderDomainNames != nil) &&
		(config.ServeHTMLFolder == "" || config.HTMLFolderDomainNames == nil) {
		return nil, fmt.Errorf("When they are provided, we need both ServeHTMLFolder and HTMLFolderDomainName filled at the same time")
	}

	allowedHeaders := strings.Join(config.AllowCustomHeaders, ",")
	if allowedHeaders != "" {
		allowedHeaders += ","
	}
	allowedHeaders += "Origin,Accept,Access-Control-Allow-Origin,Access-Control-Allow-Methods,Access-Control-Allow-Headers,Access-Control-Allow-Credentials,Accept-Encoding,Accept-Language,Access-Control-Request-Headers,Access-Control-Request-Method,Cache-Control,Connection,Host,Pragma,Referer,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Set-Cookie,User-Agent,Vary,Method,Content-Type,Content-Length"

	return &Router{
		State:                 config.State,
		serveHTMLFolder:       config.ServeHTMLFolder,
		htmlFolderDomainNames: config.HTMLFolderDomainNames,
		redirectHTTP2HTTPS:    config.RedirectHTTP2HTTPS,
		onlyHTTPS:             config.OnlyHTTPS,
		perDomainHijack:       config.PerDomainHijack,
		allowedHeaders:        allowedHeaders,
	}, nil
}

func (s *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stripedhost := utils.StripPort(r.Host)

	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}

	if strings.HasPrefix(r.URL.Path, acme.ACME_CHALLENGE_URL_PREFIX) && len(r.URL.Path) > len(acme.ACME_CHALLENGE_URL_PREFIX) {
		keyauth, err := acme.GetChallenge(stripedhost, r.URL.Path[len(acme.ACME_CHALLENGE_URL_PREFIX):])
		if err != nil {
			fmt.Println("certificates.GetChallenge", err)
			w.WriteHeader(404)
			return
		}

		w.WriteHeader(200)
		w.Write(keyauth)

		return
	}

	if r.TLS == nil {
		if s.redirectHTTP2HTTPS {
			utils.Redirect2HTTPS(w, r)
			return
		}

		if s.onlyHTTPS {
			SendError(w, "we only serve our website through https", "invalidProtocol", 403)
			return
		}
	}

	stripedhost = strings.ToLower(stripedhost)

	if r.TLS == nil {
		err := s.setupCORS(w, "http://"+stripedhost)
		if err != nil {
			SendError(w, "this origin is not allowed", "invalidOriginHeader", 403)
			return
		}
	} else {
		err := s.setupCORS(w, "https://"+stripedhost)
		if err != nil {
			SendError(w, "this origin is not allowed", "invalidOriginHeader", 403)
			return
		}
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	hs, ok := s.perDomainHijack[stripedhost]
	if ok {
		spath := utils.SplitSlash(r.URL.Path)
		for i := 0; i < len(hs); i++ {
			if !s.api(w, r, stripedhost, spath, hs[i]) {
				return
			}
		}
	}

	for i := 0; i < len(s.htmlFolderDomainNames); i++ {
		if s.htmlFolderDomainNames[i] == stripedhost {
			s.dashboard(w, r)
			return
		}
	}

	SendError(w, "we do not recognize this domain name", "invalidDomainName", 403)
	return
}

func (s *Router) dashboard(w http.ResponseWriter, r *http.Request) {
	// Check for .. in the path and respond with an error if it is present
	// otherwise users could access any file on the server
	if utils.ContainsDotDot(r.URL.Path) {
		SendError(w, "invalid Path", "invalidPath", 400)
		return
	}

	upath := r.URL.Path

	const indexPage = "index.html"

	fullName := filepath.Join(s.serveHTMLFolder, filepath.FromSlash(path.Clean(upath)))

	if fullName[len(fullName)-1] == '/' {
		fullName = filepath.Join(fullName, indexPage)
	}

	info, err := os.Stat(fullName)

	valid := false
	if err != nil || info.IsDir() {
		if err != nil && !os.IsNotExist(err) {
			SendInternalError(w, "router:dashboard", err)
			return
		}

		info, err = os.Stat(fullName + ".html")
		if err != nil || info.IsDir() {
			if err != nil && !os.IsNotExist(err) {
				SendInternalError(w, "router:dashboard", err)
				return
			}

			info, err := os.Stat(filepath.Join(fullName, indexPage))
			if err != nil || info.IsDir() {
				if err != nil && !os.IsNotExist(err) {
					SendInternalError(w, "router:dashboard", err)
					return
				}
			} else {
				fullName = filepath.Join(fullName, indexPage)
				valid = true
			}
		} else {
			fullName = fullName + ".html"
			valid = true
		}
	} else {
		valid = true
	}

	if !valid {
		// TODO: use web 404 dedicated page
		SendError(w, "page not found", "notFound", 404)
		return
	}

	content, err := os.Open(fullName)
	if err != nil {
		SendInternalError(w, "router:dashboard", err)
		return
	}

	ctype := mime.TypeByExtension(filepath.Ext(fullName))
	if ctype == "" {
		var buf [512]byte
		n, _ := io.ReadFull(content, buf[:])
		ctype = http.DetectContentType(buf[:n])

		var nn int
		for nn < n {
			l, err := w.Write(buf[nn:])
			nn += l
			if err != nil {
				SendInternalError(w, "router:dashboard", err)
				return
			}
		}
	}

	w.Header().Set("Content-Type", ctype)
	io.Copy(w, content)
}

func (s *Router) api(w http.ResponseWriter, r *http.Request, domain string, spath []string, h func(r *Router, spath []string, w http.ResponseWriter, req *http.Request, domain string) bool) bool {
	return h(s, spath, w, r, domain)
}

func (s *Router) setupCORS(w http.ResponseWriter, origin string) error {
	h := w.Header()

	// allow-Origin as wildcard and allow credentials are not allowed both at the same time.
	if origin == "" {
		return fmt.Errorf("no origin specified")
	}

	h.Add("Access-Control-Allow-Origin", origin)
	h.Add("Access-Control-Allow-Credentials", "true")

	h.Add("Access-Control-Allow-Methods", "POST, PUT, GET, DELETE, OPTIONS")
	h.Add("Access-Control-Allow-Headers", s.allowedHeaders)
	h.Add("Vary", "*")
	h.Add("Cache-Control", "no-store")

	return nil
}
