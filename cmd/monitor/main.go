package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"reflect"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/util/sets"

	"github.com/golang/glog"
	"github.com/munnerz/acme-secrets/pkg/acmeimpl"
	"github.com/munnerz/acme-secrets/pkg/watcher"
	"github.com/xenolf/lego/acme"
)

var (
	proxyURL   = flag.String("proxyURL", "", "URL to proxy connections to the apiserver")
	acmeServer = flag.String("acmeServer", "https://acme-staging.api.letsencrypt.org/directory", "the acme server to request certificates from")
	acmeEmail  = flag.String("acmeEmail", "", "the user email address for the acme server")
	acmeKey    = flag.String("acmeKey", "", "path to the file containing the users private key")
	acmeReg    = flag.String("acmeReg", "", "path to the json user registration file for acme")

	kubeClient *client.Client
)

func main() {
	flag.Parse()

	if *proxyURL != "" {
		kubeClient = client.NewOrDie(&client.Config{
			Host: *proxyURL,
		})
	} else {
		var err error
		kubeClient, err = client.NewInCluster()
		if err != nil {
			glog.Fatalf("Failed to create client: %v.", err)
		}
	}

	w, err := watcher.New(kubeClient, "default")

	if err != nil {
		glog.Fatalf("error launching apiserver watcher: %s", err.Error())
	}

	key, err := ioutil.ReadFile(*acmeKey)

	if err != nil {
		glog.Fatalf("failed reading private key: %s", err.Error())
	}

	block, _ := pem.Decode(key)

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		glog.Fatalf("error decoding private key: %s", err.Error())
	}

	regBytes, err := ioutil.ReadFile(*acmeReg)

	if err != nil {
		glog.Fatalf("error reading acme registration: %s", err.Error())
	}

	reg := new(acme.RegistrationResource)

	err = json.Unmarshal(regBytes, reg)

	if err != nil {
		glog.Fatalf("error reading user registration: %s", err.Error())
	}

	impl, err := acmeimpl.NewAcmeImpl(kubeClient, *acmeServer, acmeimpl.NewUser(*acmeEmail, privKey, reg), acme.RSA2048)

	if err != nil {
		glog.Fatalf("error initialising acme: %s", err.Error())
	}

	ctx, _ := context.WithCancel(context.Background())

	go w.WatchIngresses(ctx, time.Second*5, watcher.ChangeFuncs{
		AddFunc: func(obj interface{}) {
			if ing, ok := obj.(*extensions.Ingress); ok {
				if val, ok := ing.Labels["acme-tls"]; !ok || val != "true" {
					// only run on ingresses with acme-tls true
					return
				}
				if len(ing.Spec.TLS) > 0 {
					// TODO: if acme managed, check if certificates are valid
					// TODO: check if certificates exist
					for _, t := range ing.Spec.TLS {
						locks, err := lock(t.Hosts...)

						if err != nil {
							glog.Errorf("error acquiring lock: %s", err.Error())
							return
						}

						defer unlock(locks...)

						glog.Errorf("acquired all locks for resource: %s", ing.Name)

						certs, errs := impl.ObtainCertificates(t.Hosts...)

						if len(errs) > 0 {
							glog.Errorf("failed retreiving certificates: %s", errs)
							return
						}

						glog.Errorf("Got certs: %s", certs)
					}
				}
			} else {
				glog.Errorf("Expected object of type Ingress")
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				glog.Infof("Ingress %v changed",
					cur.(*extensions.Ingress).Name)
			}
		},
		DeleteFunc: func(obj interface{}) {
			glog.Errorf("Something deleted")
		},
	})

	<-make(chan struct{})
}

type LockResource struct {
	Secret *api.Secret
	Expiry time.Time
}

func unlockSecrets(secrets ...*api.Secret) error {
	wg := sync.WaitGroup{}
	errc := make(chan error, len(secrets))
	wg.Add(len(secrets))
	for _, res := range secrets {
		go func(lock *api.Secret) {
			defer wg.Done()
			err := releaseLock(res)

			if err != nil {
				glog.Errorf("Failed to release lock: %s", err.Error())
				return
			}
		}(res)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		return err
	}
	return nil
}

func unlock(locks ...*LockResource) error {
	secrets := make([]*api.Secret, len(locks))
	for i, l := range locks {
		secrets[i] = l.Secret
	}
	return unlockSecrets(secrets...)
}

func lock(hosts ...string) ([]*LockResource, error) {
	type result struct {
		secret *api.Secret
		expiry time.Time
		err    error
	}
	lockc := make(chan *result, len(hosts))
	wg := sync.WaitGroup{}
	wg.Add(len(hosts))
	for _, host := range hosts {
		go func(host string) {
			defer wg.Done()
			secName := fmt.Sprintf("%s-acme", host)
			lock, expiry, err := acquireLock(secName, "acme")
			lockc <- &result{lock, expiry, err}
		}(host)
	}

	wg.Wait()
	close(lockc)
	locks := make([]*LockResource, len(hosts))
	i := 0
	failed := false
	for lock := range lockc {
		if lock.err != nil {
			glog.Errorf("Error whilst acquiring lock: %s", lock.err.Error())
			failed = true
		}
		locks[i] = &LockResource{lock.secret, lock.expiry}
		i++
	}
	if failed {
		// TODO: add this ingress onto a queue to reprocess
		err := unlock(locks...)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire lock, and failed to clean up after attempting to acquire")
		}
		return nil, fmt.Errorf("failed to acquire all locks")
	}

	return locks, nil
}

// acquireLock will acquire a lock by attempting to create a secret with name `name`
// in the given namespace. If a lock with the same name already exists, it'll check
// the locks expiry time and if it's less than the current time, will acquire the lock for
// itself
func acquireLock(name, namespace string) (*api.Secret, time.Time, error) {
	var err error
	expiry, secret := createSecretLock(name, namespace)
	secret, err = kubeClient.Secrets(namespace).Create(secret)

	if err != nil {
		// another instance is likely dealing with this request
		glog.Errorf("Error creating secret lock: %s", err.Error())
		glog.Infof("Attempting cleanup of lock")

		ex, err := kubeClient.Secrets(namespace).Get(name)

		if err != nil {
			return nil, time.Now(), fmt.Errorf("secret lock has already been deleted - another instance is cleaning up: %s", err.Error())
		}

		exp, err := strconv.ParseInt(ex.Labels["acme-expiry"], 10, 64)
		if err != nil {
			return nil, time.Now(), fmt.Errorf("invalid expiry format: %s", err.Error())
		}

		expiry := time.Unix(0, exp)

		glog.Errorf("Expires: %s", expiry.String())
		if time.Now().Before(expiry) {
			return nil, time.Now(), fmt.Errorf("existing lock is still valid")
		}

		err = releaseLock(ex)

		if err != nil {
			return nil, time.Now(), fmt.Errorf("another instance has deleted the lock: %s", err.Error())
		}

		expiry, secret = createSecretLock(name, namespace)
		secret, err = kubeClient.Secrets(namespace).Create(secret)

		if err != nil {
			return nil, time.Now(), fmt.Errorf("another instance has acquired the lock: %s", err.Error())
		}
	}

	return secret, expiry, nil
}

func releaseLock(lock *api.Secret) error {
	if _, ok := lock.Labels["acme-expiry"]; !ok {
		return fmt.Errorf("missing acme-expiry label on lock")
	}

	requirement, err := labels.NewRequirement("acme-expiry", labels.EqualsOperator, sets.NewString(lock.Labels["acme-expiry"]))

	if err != nil {
		return err
	}

	return kubeClient.RESTClient.Delete().
		Namespace(lock.Namespace).
		Resource("secrets").
		Name(lock.Name).
		LabelsSelectorParam(labels.NewSelector().Add(*requirement)).
		Do().
		Error()
}

func createSecretLock(name string, namespace string) (time.Time, *api.Secret) {
	expiry := time.Now().Add(time.Second * 30)
	return expiry, &api.Secret{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: api.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"acme-managed": "true",
				"acme-lock":    "true",
				"acme-expiry":  fmt.Sprintf("%d", expiry.UnixNano()),
			},
		},
	}
}
