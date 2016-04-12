package acmeimpl

import (
	"crypto"

	"github.com/xenolf/lego/acme"
)

type CertificateRequest struct {
	IsRenewal        bool
	ExistingResource acme.CertificateResource
	Hosts            []string

	privateKey *crypto.PrivateKey
}

func NewCertificateRequest(privateKey *crypto.PrivateKey) *CertificateRequest {
	return &CertificateRequest{
		privateKey: privateKey,
	}
}
