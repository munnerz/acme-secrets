package acmeimpl

import (
	"fmt"

	"github.com/xenolf/lego/acme"

	client "k8s.io/kubernetes/pkg/client/unversioned"
)

type SecretsProvider struct {
	kubeClient *client.Client
	namespace  string
}

func (sp *SecretsProvider) Present(domain, token, keyAuth string) error {
	secret, err := sp.kubeClient.Secrets(sp.namespace).Get(fmt.Sprintf("%s-acme", domain))

	if err != nil {
		return err
	}

	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data["acme-token"] = []byte(token)
	secret.Data["acme-auth"] = []byte(keyAuth)

	secret, err = sp.kubeClient.Secrets(sp.namespace).Update(secret)

	if err != nil {
		return err
	}

	return nil
}

func (sp *SecretsProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}

func NewSecretsProvider(kubeClient *client.Client, ns string) (*SecretsProvider, error) {
	return &SecretsProvider{
		kubeClient: kubeClient,
		namespace:  ns,
	}, nil
}

type AcmeImpl struct {
	client     *acme.Client
	kubeClient *client.Client
}

func (ai *AcmeImpl) ObtainCertificates(domains ...string) (acme.CertificateResource, map[string]error) {
	return ai.client.ObtainCertificate(domains, true, nil)
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
		client:     client,
		kubeClient: kubeClient,
	}, nil
}
