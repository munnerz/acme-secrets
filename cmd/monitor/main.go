package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
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
	"github.com/munnerz/acme-secrets/pkg/acmeimpl"
	"github.com/munnerz/acme-secrets/pkg/locking"
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

	kubeLockProvider, err := locking.NewKubeProvider(kubeClient)

	if err != nil {
		glog.Fatalf("error initialising kubernetes locking provider: %s", err.Error())
	}

	lockSvc, err := locking.New(kubeLockProvider)

	if err != nil {
		glog.Fatalf("error initialisng locker: %s", err.Error())
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
				TLSLoop:
					for _, t := range ing.Spec.TLS {
						locks := make([]locking.Interface, len(t.Hosts))
						for i, host := range t.Hosts {
							lock, err := locking.NewKubeLock(createSecretLock(host, "acme"))

							if err != nil {
								glog.Errorf("error creating lock for host '%s': %s", host, err.Error())
								continue TLSLoop
							}

							locks[i] = lock
						}

						locks, errs := lockSvc.LockAll(locks...)

						if len(errs) > 0 {
							for _, err := range errs {
								glog.Errorf("error acquiring locks: %s", err.Error())
							}
							continue TLSLoop
						}

						defer lockSvc.UnlockAll(locks...)

						glog.Errorf("acquired all locks for resource: %s", ing.Name)

						certs, acmeErrs := impl.ObtainCertificates(t.Hosts...)

						if len(acmeErrs) > 0 {
							for _, err := range acmeErrs {
								glog.Errorf("failed retreiving certificates: %s", err.Error())
							}
							continue TLSLoop
						}

						secret := createSecret(t.SecretName, ing.Namespace, certs.Certificate, certs.PrivateKey)

						secret, err = kubeClient.Secrets(ing.Namespace).Create(secret)

						if err != nil {
							glog.Errorf("error saving certificate to kubernetes: %s", err)
							continue TLSLoop
						}

						glog.Errorf("Successfully saved secret %s", secret.Name)
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

func createSecret(name, namespace string, cert, key []byte) *api.Secret {
	return &api.Secret{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: api.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"acme-managed": "true",
			},
		},
		Data: map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
		},
	}
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
