package locking

import (
	"fmt"
	"strconv"
	"time"

	"k8s.io/kubernetes/pkg/api"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/util/sets"
)

type KubeProvider struct {
	kubeClient *client.Client
}

// Lock will acquire a lock by attempting to create a secret with name `name`
// in the given namespace. If a lock with the same name already exists, it'll check
// the locks expiry time and if it's less than the current time, will acquire the lock for
// itself
func (kp *KubeProvider) Lock(lock Interface) (Interface, error) {
	var secret, newSecret *api.Secret
	var ok bool
	var err error
	if secret, ok = lock.GetObject().(*api.Secret); !ok {
		return lock, fmt.Errorf("expected lock resource of type *api.Secret")
	}

	newSecret, err = kp.kubeClient.Secrets(secret.Namespace).Create(secret)

	if err != nil {
		ex, err := kp.kubeClient.Secrets(secret.Namespace).Get(secret.Name)

		if err != nil {
			return nil, fmt.Errorf("secret lock has already been deleted: %s", err.Error())
		}

		if existingExpiry, err := lockExpiry(ex); err == nil {
			if time.Now().Before(existingExpiry) {
				return nil, fmt.Errorf("existing lock is still valid, expires: %s", existingExpiry.String())
			}
		}

		err = kp.releaseKubeLock(ex)

		if err != nil {
			return nil, fmt.Errorf("secret lock has already been deleted: %s", err.Error())
		}

		newSecret, err = kp.kubeClient.Secrets(secret.Namespace).Create(secret)

		if err != nil {
			return nil, fmt.Errorf("another instance has acquired the lock: %s", err.Error())
		}
	}

	if lock, err = NewKubeLock(newSecret); err != nil {
		return nil, fmt.Errorf("invalid response from kube apiserver: %s", err.Error())
	}

	return lock, nil
}

func (kp *KubeProvider) Unlock(lock Interface) (Interface, error) {
	var secret *api.Secret
	var ok bool

	if secret, ok = lock.GetObject().(*api.Secret); !ok {
		return lock, fmt.Errorf("expected lock resource of type *api.Secret")
	}

	return lock, kp.releaseKubeLock(secret)
}

func (kp *KubeProvider) releaseKubeLock(lock *api.Secret) error {
	if _, ok := lock.Labels["acme-expiry"]; !ok {
		return fmt.Errorf("missing acme-expiry label on lock")
	}

	requirement, err := labels.NewRequirement("acme-expiry", labels.EqualsOperator, sets.NewString(lock.Labels["acme-expiry"]))

	if err != nil {
		return err
	}

	return kp.kubeClient.RESTClient.Delete().
		Namespace(lock.Namespace).
		Resource("secrets").
		Name(lock.Name).
		LabelsSelectorParam(labels.NewSelector().Add(*requirement)).
		Do().
		Error()
}

func lockExpiry(s *api.Secret) (time.Time, error) {
	if exp, ok := s.Labels["acme-expiry"]; ok {
		return expiryToTime(exp)
	} else {
		return time.Time{}, fmt.Errorf("no expiry label set on secret")
	}
}

func expiryToTime(exp string) (time.Time, error) {
	i, err := strconv.ParseInt(exp, 10, 64)

	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, i), nil
}

func timeToExpiry(t time.Time) string {
	return fmt.Sprintf("%d", t.UnixNano())
}

func NewKubeProvider(kubeClient *client.Client) (*KubeProvider, error) {
	return &KubeProvider{
		kubeClient: kubeClient,
	}, nil
}
