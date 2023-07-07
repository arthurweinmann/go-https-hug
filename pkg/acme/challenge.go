package acme

import (
	"time"
)

type HTTPChallenger struct {
}

func (c *HTTPChallenger) Present(domain, token, keyAuth string) error {
	return settings.Store.SetKV("challenges/"+domain+"_"+token, []byte(keyAuth), 30*time.Minute)
}

func (c *HTTPChallenger) CleanUp(domain, token, keyAuth string) error {
	return settings.Store.DeleteKV("challenges/" + domain + "_" + token)
}

func GetChallenge(domain, token string) ([]byte, error) {
	return settings.Store.GetKV("challenges/" + domain + "_" + token)
}
