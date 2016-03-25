package locking

import (
	"strconv"
	"time"

	"k8s.io/kubernetes/pkg/api"
)

type KubeLock struct {
	secret *api.Secret
	expiry time.Time
}

func (k *KubeLock) GetObject() interface{} {
	return k.secret
}

func (k *KubeLock) GetExpiry() time.Time {
	return k.expiry
}

func NewKubeLock(sec *api.Secret) (*KubeLock, error) {
	t, err := strconv.ParseInt(sec.Labels["acme-expiry"], 10, 64)

	if err != nil {
		return nil, err
	}

	return &KubeLock{
		secret: sec,
		expiry: time.Unix(0, t),
	}, nil
}
