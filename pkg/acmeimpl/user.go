package acmeimpl

import (
	"crypto"

	"github.com/xenolf/lego/acme"
)

// You'll need a user or account type that implements acme.User
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewUser(email string, privKey crypto.PrivateKey, reg *acme.RegistrationResource) User {
	return User{
		Email:        email,
		key:          privKey,
		Registration: reg,
	}
}
