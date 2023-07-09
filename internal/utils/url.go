package utils

import (
	"net/url"
	"strings"
)

func SplitSlash(url string) []string {
	if url == "" || url == "/" {
		return []string{"/"}
	}

	splitedURL := strings.Split(url, "/")

	if splitedURL[0] == "" {
		splitedURL = splitedURL[1:]
	}

	if splitedURL[len(splitedURL)-1] == "" {
		splitedURL = splitedURL[:len(splitedURL)-1]
	}

	return splitedURL
}

// StripPort also removes IPV6 addresses square brackets
func StripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

func SplitHostPort(hostport string) (string, string) {
	spl := strings.Split(hostport, ":")
	if len(spl) == 1 {
		return spl[0], ""
	}

	return spl[0], spl[1]
}

func BreakBaseURL(rawurl string) (scheme, ipaddr, port string, err error) {
	var u *url.URL
	u, err = url.ParseRequestURI(rawurl)
	if err != nil || u.Host == "" {
		u, repErr := url.ParseRequestURI("https://" + rawurl)
		if repErr != nil {
			return
		}
		ipaddr, port = SplitHostPort(u.Host)
		err = nil
		return
	}

	ipaddr, port = SplitHostPort(u.Host)
	scheme = u.Scheme
	return
}
