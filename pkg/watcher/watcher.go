package watcher

import client "k8s.io/kubernetes/pkg/client/unversioned"

func New(client *client.Client, namespace string) (*Watcher, error) {
	return &Watcher{
		kubeClient: client,
	}, nil
}
