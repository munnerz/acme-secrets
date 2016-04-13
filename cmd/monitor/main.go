package monitor

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
	"time"

	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"

	"github.com/golang/glog"
	"github.com/hashicorp/go-multierror"
	"github.com/munnerz/kube-acme/pkg/acmeimpl"
	"github.com/munnerz/kube-acme/pkg/locking"
	"github.com/munnerz/kube-acme/pkg/monitor"
	"github.com/munnerz/kube-acme/pkg/watcher"
	"github.com/namsral/flag"
	"github.com/xenolf/lego/acme"
)

var (
	acmeServer     = flag.String("acmeServer", "https://acme-staging.api.letsencrypt.org/directory", "the acme server to request certificates from")
	acmeEmail      = flag.String("acmeEmail", "", "the user email address for the acme server")
	acmeKey        = flag.String("acmeKey", "/config/private.key", "path to the file containing the users private key")
	acmeReg        = flag.String("acmeReg", "/config/acme-reg.json", "path to the json user registration file for acme")
	renewThreshold = flag.Duration("renewPeriod", time.Hour*24*30, "begin attempting to renew certificates this long before they expire")

	kubeClient *client.Client
	acmeImpl   *acmeimpl.AcmeImpl
	lockSvc    *locking.Locking
)

func Main(proxyURL *string) {
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

	acmeImpl, err = initAcmeImpl()

	if err != nil {
		glog.Fatalf("error initialising acmeimpl: %s", err.Error())
	}

	lockSvc, err = initKubeLockService(kubeClient)

	if err != nil {
		glog.Fatalf("error initialisng lock service: %s", err.Error())
	}

	ctx, _ := context.WithCancel(context.Background())

	go w.WatchIngresses(ctx, time.Second*5, watcher.ChangeFuncs{
		AddFunc: addIngFunc,
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				glog.Infof("Ingress %v changed",
					cur.(*extensions.Ingress).Name)
				addIngFunc(cur)
			}
		},
		DeleteFunc: func(obj interface{}) {},
	})

	<-make(chan struct{})
}

func initAcmeImpl() (*acmeimpl.AcmeImpl, error) {
	privKey, err := loadAcmePrivateKey(*acmeKey)

	if err != nil {
		glog.Fatalf("error loading acme private key: %s", err.Error())
	}

	reg, err := loadAcmeRegistration(*acmeReg)

	if err != nil {
		glog.Fatalf("error loading acme registration: %s", err.Error())
	}

	return acmeimpl.NewAcmeImpl(kubeClient, *acmeServer, acmeimpl.NewUser(*acmeEmail, privKey, reg), acme.RSA2048)

}

func initKubeLockService(client *client.Client) (*locking.Locking, error) {
	klp, err := locking.NewKubeProvider(client)

	if err != nil {
		return nil, fmt.Errorf("error initialising kubernetes locking provider: %s", err.Error())
	}

	lockSvc, err := locking.New(klp)

	if err != nil {
		fmt.Errorf("error initialisng locker: %s", err.Error())
	}

	return lockSvc, nil
}

func loadAcmePrivateKey(file string) (crypto.PrivateKey, error) {
	key, err := ioutil.ReadFile(file)

	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %s", err.Error())
	}

	return parsePEMPrivateKey(key)
}

func parsePEMPrivateKey(key []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(key)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("Unknown PEM header value")
	}
}

func loadAcmeRegistration(file string) (*acme.RegistrationResource, error) {
	regBytes, err := ioutil.ReadFile(file)

	if err != nil {
		return nil, fmt.Errorf("error reading acme registration: %s", err.Error())
	}

	reg := new(acme.RegistrationResource)

	err = json.Unmarshal(regBytes, reg)

	if err != nil {
		return nil, fmt.Errorf("error reading user registration: %s", err.Error())
	}

	return reg, nil
}

func acquireAllLocks(names []string) ([]locking.Interface, error) {
	locks := make([]locking.Interface, len(names))

	for i, name := range names {
		lock, err := locking.NewKubeLock(createSecretLock(name, "acme"))

		if err != nil {
			return nil, fmt.Errorf("error creating lock with name '%s': %s", name, err.Error())
		}

		locks[i] = lock
	}

	locks, errs := lockSvc.LockAll(locks...)

	if len(errs) > 0 {
		return nil, errors.New(multierror.ListFormatFunc(errs))
	}

	return locks, nil
}

func getCertificateRequest(name, namespace string, hosts []string) (*acmeimpl.CertificateRequest, bool, error) {
	existingSecret, err := kubeClient.Secrets(namespace).Get(name)

	cr := &acmeimpl.CertificateRequest{
		Hosts: hosts,
	}

	if err != nil {
		return cr, false, nil
	}

	if !isAcmeManaged(existingSecret) {
		return nil, true, fmt.Errorf("secret '%s' already exists and is not acme managed. skipping", name)
	}

	tlsSecret, err := monitor.TLSSecretFromSecret(existingSecret)

	if err != nil {
		return cr, true, nil
	}

	expiry, err := tlsSecret.Expiry()

	if err != nil {
		return cr, true, nil
	}

	privKey, err := parsePEMPrivateKey(tlsSecret.PrivateKey())

	if err != nil {
		return cr, true, nil
	}

	if time.Now().Add(*renewThreshold).Before(expiry) {
		return nil, true, fmt.Errorf("secret '%s' already exists and is valid until %s", name, expiry)
	}

	return &acmeimpl.CertificateRequest{
		Hosts:            hosts,
		IsRenewal:        true,
		ExistingResource: tlsSecret.CertificateResource,
		PrivateKey:       &privKey,
	}, true, nil
}

func addIngFunc(obj interface{}) {
	if ing, ok := obj.(*extensions.Ingress); ok {
		if val, ok := ing.Labels["acme-tls"]; !ok || val != "true" {
			// only run on ingresses with acme-tls true
			return
		}
		if len(ing.Spec.TLS) > 0 {
		TLSLoop:
			for _, t := range ing.Spec.TLS {
				certRequest, secretExists, err := getCertificateRequest(t.SecretName, ing.Namespace, t.Hosts)
				if err != nil {
					glog.Errorf("[%s] not requesting certificate for hosts %s: %s", t.SecretName, t.Hosts, err.Error())
					continue TLSLoop
				}

				locks, err := acquireAllLocks(t.Hosts)

				if err != nil {
					glog.Errorf("[%s] failed to acquire all locks for ingress: %s", t.SecretName, err.Error())
					continue TLSLoop
				}

				defer func() {
					_, errs := lockSvc.UnlockAll(locks...)
					for _, err := range errs {
						glog.Errorf("[%s] error releasing lock: %s", t.SecretName, err.Error())
					}
				}()

				glog.Errorf("[%s] acquired all locks for resource: %s", t.SecretName, ing.Name)

				certs, err := acmeImpl.Perform(certRequest)

				if err != nil {
					glog.Errorf("[%s] failed to obtain certificate for hosts '%s': %s", t.SecretName, t.Hosts, err.Error())
					// TODO: because we unlock in a defer func, they will not be released until
					// after attempting to obtain certificates for the entire Ingress resource
					continue TLSLoop
				}

				tlsSecret := monitor.DefaultTLSSecret{
					Name:                t.SecretName,
					Namespace:           ing.Namespace,
					CertificateResource: certs,
				}

				secret, err := tlsSecret.Secret()

				if err != nil {
					glog.Errorf("[%s] failed to create ingress secret: %s", tlsSecret.Name, err.Error())
					continue TLSLoop
				}

				if secretExists {
					secret, err = kubeClient.Secrets(secret.Namespace).Update(secret)
				} else {
					secret, err = kubeClient.Secrets(secret.Namespace).Create(secret)
				}

				if err != nil {
					glog.Errorf("[%s] error saving certificate to kubernetes: %s", t.SecretName, err)
					continue TLSLoop
				}

				glog.Errorf("[%s] Successfully saved secret", secret.Name)
			}
		}
	} else {
		glog.Errorf("Expected object of type Ingress")
	}
}

func isAcmeManaged(s *api.Secret) bool {
	if s.Labels == nil {
		return false
	}
	if exp, ok := s.Labels["acme-managed"]; ok {
		if exp == "true" {
			return true
		}
	}
	return false
}

func createSecretLock(name, namespace string) *api.Secret {
	return &api.Secret{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: api.ObjectMeta{
			Name:      fmt.Sprintf("%s-acme", name),
			Namespace: namespace,
			Labels: map[string]string{
				"acme-managed": "true",
				"acme-lock":    "true",
				"acme-expiry":  fmt.Sprintf("%d", time.Now().Add(time.Second*30).UnixNano()),
			},
		},
	}
}
