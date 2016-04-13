package acmeimpl

import (
	"crypto"

	"github.com/xenolf/lego/acme"
)

type CertificateRequest struct {
	IsRenewal        bool
	ExistingResource acme.CertificateResource
	Hosts            []string
	PrivateKey       crypto.PrivateKey
}
