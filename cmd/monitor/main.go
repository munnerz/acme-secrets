package monitor

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func loadAcmePrivateKey(file string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(file)

	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %s", err.Error())
	}

	block, _ := pem.Decode(key)

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %s", err.Error())
	}

	return privKey, nil
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

func addIngFunc(obj interface{}) {
	if ing, ok := obj.(*extensions.Ingress); ok {
		if val, ok := ing.Labels["acme-tls"]; !ok || val != "true" {
			// only run on ingresses with acme-tls true
			return
		}
		if len(ing.Spec.TLS) > 0 {
		TLSLoop:
			for _, t := range ing.Spec.TLS {
				renew, update := false, false
				existingSecret, err := getSecret(t.SecretName, ing.Namespace)
				if err == nil {
					if isAcmeManaged(existingSecret) {
						cert, err := tlsCertificate(existingSecret)

						if err == nil {
							if time.Now().Add(*renewThreshold).After(cert.NotAfter) {
								renew = true
							} else {
								glog.Infof("[%s] existing certificate still valid. skipping...", t.SecretName)
								continue TLSLoop
							}
						} else {
							glog.Errorf("update due to err: %s", err.Error())
							update = true
						}

					} else {
						glog.Infof("[%s] existing secret marked as not managed by acme-tls already exists. skipping for safety...", t.SecretName)
						continue TLSLoop
					}
				}

				locks := make([]locking.Interface, len(t.Hosts))
				for i, host := range t.Hosts {
					lock, err := locking.NewKubeLock(createSecretLock(host, "acme"))

					if err != nil {
						glog.Errorf("[%s] error creating lock for host '%s': %s", t.SecretName, host, err.Error())
						continue TLSLoop
					}

					locks[i] = lock
				}

				locks, errs := lockSvc.LockAll(locks...)

				if len(errs) > 0 {
					for _, err := range errs {
						glog.Errorf("[%s] error acquiring lock: %s", t.SecretName, err.Error())
					}
					continue TLSLoop
				}

				defer func() {
					_, errs := lockSvc.UnlockAll(locks...)
					for _, err := range errs {
						glog.Errorf("[%s] error releasing lock: %s", t.SecretName, err.Error())
					}
				}()

				glog.Errorf("[%s] acquired all locks for resource: %s", t.SecretName, ing.Name)

				var certs acme.CertificateResource
				var acmeErrs map[string]error
				if renew {
					cr, err := getCertificateResource(existingSecret)

					if err != nil {
						glog.Errorf("[%s] error decoding certificate resource: %s", t.SecretName, err.Error())
						continue TLSLoop
					}

					cr.Certificate, err = getCertificateBytes(existingSecret)

					if err != nil {
						glog.Errorf("[%s] error retreiving existing tls certificate: %s", t.SecretName, err.Error())
						continue TLSLoop
					}

					// ignore errors as a nil key will cause acme to generate a new one
					cr.PrivateKey, _ = getPrivateKeyBytes(existingSecret)

					certs, err = acmeImpl.RenewCertificate(*cr, true)

					if err != nil {
						glog.Errorf("[%s] failed renewing certificate: %s", t.SecretName, err.Error())
						continue TLSLoop
					}

					glog.Errorf("[%s] renewed certificate for hosts: %s", t.SecretName, t.Hosts)
				} else {
					certs, acmeErrs = acmeImpl.ObtainCertificate(t.Hosts, true, nil)
					if len(acmeErrs) > 0 {
						for _, err := range acmeErrs {
							glog.Errorf("failed retreiving certificates: %s", err.Error())
						}
						continue TLSLoop
					}

					glog.Errorf("[%s] obtained certificate for hosts: %s", t.SecretName, t.Hosts)
				}

				secret, err := createSecret(t.SecretName, ing.Namespace, certs)

				if err != nil {
					glog.Errorf("[%s] failed to create ingress secret: %s", t.SecretName, err.Error())
					continue TLSLoop
				}

				if update || renew {
					secret, err = kubeClient.Secrets(ing.Namespace).Update(secret)
				} else {
					secret, err = kubeClient.Secrets(ing.Namespace).Create(secret)
				}

				if err != nil {
					glog.Errorf("[%s] error saving certificate to kubernetes: %s", t.SecretName, err)
					continue TLSLoop
				}

				glog.Errorf("[%s] Successfully saved secret %s", t.SecretName, secret.Name)
			}
		}
	} else {
		glog.Errorf("Expected object of type Ingress")
	}
}

func getCertificateResource(s *api.Secret) (*acme.CertificateResource, error) {
	nocr := fmt.Errorf("no certificate resource found on secret")
	if s.Data == nil {
		return nil, nocr
	}
	if crb, ok := s.Data["acme.certificate-resource"]; ok {
		cr := new(acme.CertificateResource)

		if err := json.Unmarshal(crb, cr); err != nil {
			return nil, err
		}

		return cr, nil
	}
	return nil, nocr
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

func getCertificateBytes(s *api.Secret) ([]byte, error) {
	nocrt := fmt.Errorf("no tls certificate exists")
	if s.Data == nil {
		return nil, nocrt
	}

	if crtb, ok := s.Data["tls.crt"]; ok {
		return crtb, nil
	}
	return nil, nocrt
}

func getPrivateKeyBytes(s *api.Secret) ([]byte, error) {
	nokey := fmt.Errorf("no tls key exists")
	if s.Data == nil {
		return nil, nokey
	}

	if crtb, ok := s.Data["tls.key"]; ok {
		return crtb, nil
	}
	return nil, nokey
}

func tlsCertificate(s *api.Secret) (*x509.Certificate, error) {
	var b []byte
	var err error
	if b, err = getCertificateBytes(s); err == nil {
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)

		if err != nil {
			return nil, err
		}

		return cert, nil
	}
	return nil, err
}

func getSecret(name, namespace string) (*api.Secret, error) {
	return kubeClient.Secrets(namespace).Get(fmt.Sprintf("%s", name))
}

func createSecret(name, namespace string, cr acme.CertificateResource) (*api.Secret, error) {
	crBytes, err := json.Marshal(cr)

	if err != nil {
		return nil, err
	}

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
			"acme.certificate-resource": crBytes,
			"tls.crt":                   cr.Certificate,
			"tls.key":                   cr.PrivateKey,
		},
	}, nil
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
