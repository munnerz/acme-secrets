package watcher

import (
	client "k8s.io/kubernetes/pkg/client/unversioned"
)

type Watcher struct {
	kubeClient *client.Client
	namespace  string
}

type ChangeFuncs struct {
	AddFunc    func(interface{})
	DeleteFunc func(interface{})
	UpdateFunc func(interface{}, interface{})
}
