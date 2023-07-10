package utils

import "net/http"

func Redirect2HTTPS(w http.ResponseWriter, req *http.Request) {
	scheme := "https"

	if req.URL.Scheme == "ws" {
		scheme = "wss"
	}

	// remove/add not default ports from req.Host
	target := scheme + "://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}
	if len(req.URL.RawFragment) > 0 {
		target += "#" + req.URL.RawFragment
	}
	http.Redirect(w, req, target,
		// consider the codes 308, 302, or 301
		http.StatusTemporaryRedirect)
}
