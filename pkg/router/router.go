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

	serveHTMLFolder      string
	htmlFolderDomainName string
	redirectHTTP2HTTPS   bool
	perDomain            map[string]func(r *Router, spath []string, w http.ResponseWriter, req *http.Request)
}

type RouterConfig struct {
	// any struct or map you may need
	State any

	// folder path
	ServeHTMLFolder      string
	HTMLFolderDomainName string

	RedirectHTTP2HTTPS bool

	PerDomain map[string]func(r *Router, spath []string, w http.ResponseWriter, req *http.Request)
}

func NewRouter(config *RouterConfig) (*Router, error) {
	if (config.ServeHTMLFolder != "" || config.HTMLFolderDomainName != "") &&
		(config.ServeHTMLFolder == "" || config.HTMLFolderDomainName == "") {
		return nil, fmt.Errorf("When they are provided, we need both ServeHTMLFolder and HTMLFolderDomainName filled at the same time")
	}

	return &Router{
		State:                config.State,
		serveHTMLFolder:      config.ServeHTMLFolder,
		htmlFolderDomainName: config.HTMLFolderDomainName,
		redirectHTTP2HTTPS:   config.RedirectHTTP2HTTPS,
		perDomain:            config.PerDomain,
	}, nil
}

func (s *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stripedhost := utils.StripPort(r.Host)

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

	if s.redirectHTTP2HTTPS && r.URL.Scheme != "https" && r.URL.Scheme != "wss" {
		utils.Redirect2HTTPS(w, r)
		return
	}

	stripedhost = strings.ToLower(stripedhost)
	h, ok := s.perDomain[stripedhost]
	if ok {
		s.api(w, r, stripedhost, h)
	}

	if stripedhost == s.htmlFolderDomainName {
		s.dashboard(w, r)
		return
	}

	utils.SendError(w, "we do not recognize this domain name", "invalidDomainName", 403)
	return
}

func (s *Router) dashboard(w http.ResponseWriter, r *http.Request) {
	// Check for .. in the path and respond with an error if it is present
	// otherwise users could access any file on the server
	if utils.ContainsDotDot(r.URL.Path) {
		utils.SendError(w, "invalid Path", "invalidPath", 400)
		return
	}

	err := s.setupCORS(w, s.htmlFolderDomainName)
	if err != nil {
		utils.SendError(w, "this origin is not allowed", "invalidOriginHeader", 403)
		return
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	upath := r.URL.Path

	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	const indexPage = "index.html"

	fullName := filepath.Join(s.serveHTMLFolder, filepath.FromSlash(path.Clean(upath)))

	if fullName[len(fullName)-1] == '/' {
		fullName = filepath.Join(fullName, indexPage)
	}

	info, err := os.Stat(fullName)

	valid := false
	if err != nil || info.IsDir() {
		if err != nil && !os.IsNotExist(err) {
			utils.SendInternalError(w, "router:dashboard", err)
			return
		}

		info, err = os.Stat(fullName + ".html")
		if err != nil || info.IsDir() {
			if err != nil && !os.IsNotExist(err) {
				utils.SendInternalError(w, "router:dashboard", err)
				return
			}

			info, err := os.Stat(filepath.Join(fullName, indexPage))
			if err != nil || info.IsDir() {
				if err != nil && !os.IsNotExist(err) {
					utils.SendInternalError(w, "router:dashboard", err)
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
		utils.SendError(w, "page not found", "notFound", 404)
		return
	}

	content, err := os.Open(fullName)
	if err != nil {
		utils.SendInternalError(w, "router:dashboard", err)
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
				utils.SendInternalError(w, "router:dashboard", err)
				return
			}
		}
	}

	w.Header().Set("Content-Type", ctype)
	io.Copy(w, content)
}

func (s *Router) api(w http.ResponseWriter, r *http.Request, domain string, h func(r *Router, spath []string, w http.ResponseWriter, req *http.Request)) {
	spath := utils.SplitSlash(r.URL.Path)

	err := s.setupCORS(w, domain)
	if err != nil {
		utils.SendError(w, "this origin is not allowed", "invalidOriginHeader", 403)
		return
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	h(s, spath, w, r)
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
	h.Add("Access-Control-Allow-Headers", "Origin,Accept,Access-Control-Allow-Origin,Access-Control-Allow-Methods,Access-Control-Allow-Headers,Access-Control-Allow-Credentials,Accept-Encoding,Accept-Language,Access-Control-Request-Headers,Access-Control-Request-Method,Cache-Control,Connection,Host,Pragma,Referer,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Set-Cookie,User-Agent,Vary,Method,Content-Type,Content-Length")
	h.Add("Vary", "*")
	h.Add("Cache-Control", "no-store")

	return nil
}
