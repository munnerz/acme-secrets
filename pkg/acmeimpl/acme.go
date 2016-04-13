package acmeimpl

import (
	"github.com/xenolf/lego/acme"

	client "k8s.io/kubernetes/pkg/client/unversioned"
)

type Interface interface {
	Perform(*CertificateRequest) (*acme.CertificateResource, error)
}

type AcmeImpl struct {
	*acme.Client
	kubeClient *client.Client
}

func (a *AcmeImpl) Perform(cr *CertificateRequest) (acme.CertificateResource, error) {
	if cr.IsRenewal {
		return a.RenewCertificate(cr.ExistingResource, true)
	}

	res, errs := a.ObtainCertificate(cr.Hosts, true, cr.PrivateKey)

	return res, mapErrsToErr(errs)
}

func NewAcmeImpl(kubeClient *client.Client, server string, user User, rsaKeySize acme.KeyType) (*AcmeImpl, error) {
	client, err := acme.NewClient(server, &user, rsaKeySize)

	if err != nil {
		return nil, err
	}

	sp, err := NewSecretsProvider(kubeClient, "acme")

	if err != nil {
		return nil, err
	}

	client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
	client.SetChallengeProvider(acme.HTTP01, sp)

	return &AcmeImpl{
		Client:     client,
		kubeClient: kubeClient,
	}, nil
}
