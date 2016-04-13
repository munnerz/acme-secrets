package acmeimpl

import (
	"fmt"

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
