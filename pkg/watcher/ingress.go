package watcher

import (
	"time"

	"golang.org/x/net/context"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
)

func (w *Watcher) WatchIngresses(ctx context.Context, resyncPeriod time.Duration, c ChangeFuncs) {
	ingHandlers := framework.ResourceEventHandlerFuncs{
		AddFunc:    c.AddFunc,
		DeleteFunc: c.DeleteFunc,
		UpdateFunc: c.UpdateFunc,
	}

	_, ctrl := framework.NewInformer(
		&cache.ListWatch{
			ListFunc:  ingressListFunc(w.kubeClient, w.namespace),
			WatchFunc: ingressWatchFunc(w.kubeClient, w.namespace),
		},
		&extensions.Ingress{}, resyncPeriod, ingHandlers)

	ctrl.Run(ctx.Done())
}

func ingressListFunc(c *client.Client, ns string) func(api.ListOptions) (runtime.Object, error) {
	return func(opts api.ListOptions) (runtime.Object, error) {
		return c.Extensions().Ingress(ns).List(opts)
	}
}

func ingressWatchFunc(c *client.Client, ns string) func(options api.ListOptions) (watch.Interface, error) {
	return func(options api.ListOptions) (watch.Interface, error) {
		return c.Extensions().Ingress(ns).Watch(options)
	}
}
