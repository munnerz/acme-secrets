package monitor

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xenolf/lego/acme"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

// TLSSecret Interface for mocking in tests
type TLSSecret interface {
	Expiry() (time.Time, error)
	Secret() (*api.Secret, error)

	Certificate() []byte
	PrivateKey() []byte
}

// DefaultTLSSecret is the default TLSSecret implementation
type DefaultTLSSecret struct {
	Name      string
	Namespace string

	CertificateResource acme.CertificateResource
}

// Expiry returns the expiry date of the certificate, or an error
// if parsing the certificate fails
func (t *DefaultTLSSecret) Expiry() (time.Time, error) {
	return acme.GetPEMCertExpiration(t.CertificateResource.Certificate)
}

func (t *DefaultTLSSecret) Certificate() []byte {
	if cert := t.CertificateResource.Certificate; len(cert) > 0 {
		return cert
	}
	return nil
}

func (t *DefaultTLSSecret) PrivateKey() []byte {
	if cert := t.CertificateResource.PrivateKey; len(cert) > 0 {
		return cert
	}
	return nil
}

// Secret returns a complete Kubernetes Secret object for this
// tls resource
func (t *DefaultTLSSecret) Secret() (*api.Secret, error) {
	if len(t.Name) == 0 {
		return nil, fmt.Errorf("TLSSecret name must be set")
	}

	crBytes, err := json.Marshal(t.CertificateResource)

	if err != nil {
		return nil, err
	}

	return &api.Secret{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: api.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
			Labels: map[string]string{
				"acme-managed": "true",
			},
		},
		Data: map[string][]byte{
			"acme.certificate-resource": crBytes,
			"tls.crt":                   t.CertificateResource.Certificate,
			"tls.key":                   t.CertificateResource.PrivateKey,
		},
	}, nil
}

func TLSSecretFromSecret(secret *api.Secret) (*DefaultTLSSecret, error) {
	cr, err := getCertificateResource(secret)

	if err != nil {
		return nil, err
	}

	return &DefaultTLSSecret{
		Name:                secret.Name,
		Namespace:           secret.Namespace,
		CertificateResource: *cr,
	}, nil
}

func getCertificateResource(s *api.Secret) (*acme.CertificateResource, error) {
	nocr := fmt.Errorf("no certificate resource data found on secret")
	if s.Data == nil {
		return nil, nocr
	}

	cr := new(acme.CertificateResource)
	var crb []byte
	var ok bool

	if crb, ok = s.Data["acme.certificate-resource"]; !ok {
		return nil, nocr
	}

	if err := json.Unmarshal(crb, cr); err != nil {
		return nil, err
	}

	if crt, ok := s.Data["tls.crt"]; ok {
		cr.Certificate = crt
	}

	if key, ok := s.Data["tls.key"]; ok {
		cr.PrivateKey = key
	}

	return cr, nil
}
