package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/go-acme/lego/v4/registration"
)

type ACMEUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          string                 `json:"key"`

	key *ecdsa.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *ACMEUser) Save() error {
	u.Key = encode(u.key)
	defer func() {
		u.Key = ""
	}()

	b, err := json.Marshal(u)
	if err != nil {
		return err
	}

	return settings.Store.SetKV("user/account.json", b, 0)
}

func loadACMEUserFromDisk() (*ACMEUser, error) {
	b, err := settings.Store.GetKV("user/account.json")
	if err != nil {
		return nil, err
	}

	u := &ACMEUser{}
	err = json.Unmarshal(b, u)
	if err != nil {
		return nil, err
	}

	u.key = decode(u.Key)
	u.Key = ""

	return u, nil
}

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decode(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return privateKey
}
