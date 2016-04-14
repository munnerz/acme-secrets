# kube-acme [![Build Status](https://travis-ci.org/munnerz/kube-acme.svg?branch=master)](https://travis-ci.org/munnerz/kube-acme)

_STILL IN DEVELOPMENT_

kube-acme allows you to enable TLS for your Kubernetes services, without having to think about it.

An acme client that integrates with Kubernetes to automatically generate and renew certificates and store them in secrets to be served by whichever ingress controller you use.

## Current features

* Automatically retreive TLS certificates from an ACME server
* Plug in to existing ingress controllers

## Planned features

* Renew certificates automatically every x days
* Regularly monitoring existing Ingress resources to ensure they're up to date
* TLSSNI01 support
* Automatic configuration of Ingress resources to add the /.well-known/acme-challenge endpoint
* Automatically retreive and store user account and private key to ease setup

## Usage

### Initial setup

At the moment kube-acme is to some extent limited by namespaces, and aspecially the inability
of ingress to reference service from different namespace. This means that for an ingress
to be able to properly work, a "local" (as in the "same namespace") kube-acme service is required.
Still, to properly establish locks, a dedicated "acme" namespace is expected to exist.

```
kind: Namespace
apiVersion: v1
metadata:
  name: acme
```

To connect to the acme server a registers user is required (while this will most likely be handled by `kube-acme` in future,
at the moment a secret has to be created containing all the required information like in example below

```
apiVersion: v1
kind: Secret
metadata:
  name: kube-acme-user
type: Opaque
data:
  private.key: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRDNTRZbi9hdU1IMUNFMmJuRmN0ZGE2TnIydFFtbElMeVUzVlA2Nm5pZXA0dUJMRVdxb2IwdmQKMHViNWhOL0pVTCtnQndZRks0RUVBQ0toWkFOaUFBUjFQR1ZvNi9lYy9wR0svMEV3TW9Ud2xwU0Vtcy9USG5VWgpuUWMyUHhXK20wTHhlQlFzZ1hROEJWbVpjRmcrS1E4cHQ4NXpEbjhJWlJwVDNQVXBoeGhucnpiNmJtMzIvWTQwCnhEVWRUL2kxOUp0QzBjRDJyamc0S0w3N1dYdFQraTQ9Ci0tLS0tRU5EIEVDIFBSSVZBVEUgS0VZLS0tLS0K
  acme-reg.json: ewogICJ0ZXJtc19vZl9zZXJ2aWNlIjogImh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL2RvY3VtZW50cy9MRS1TQS12MS4wLjEtSnVseS0yNy0yMDE1LnBkZiIsCiAgIm5ld19hdXRoenJfdXJpIjogImh0dHBzOi8vYWNtZS1zdGFnaW5nLmFwaS5sZXRzZW5jcnlwdC5vcmcvYWNtZS9uZXctYXV0aHoiLAogICJ1cmkiOiAiaHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL3JlZy8xNzg5NzkiLAogICJib2R5IjogewogICAgImFncmVlbWVudCI6ICJodHRwczovL2xldHNlbmNyeXB0Lm9yZy9kb2N1bWVudHMvTEUtU0EtdjEuMC4xLUp1bHktMjctMjAxNS5wZGYiLAogICAgImNvbnRhY3QiOiBbCiAgICAgICJtYWlsdG86ZGVtb0BkZW1vLmNvbSIKICAgIF0sCiAgICAia2V5IjogewogICAgICAieSI6ICJLYmZPY3c1X0NHVWFVOXoxS1ljWVo2ODItbTV0OXYyT05NUTFIVV80dGZTYlF0SEE5cTQ0T0NpLS0xbDdVX291IiwKICAgICAgIngiOiAiZFR4bGFPdjNuUDZSaXY5Qk1ES0U4SmFVaEpyUDB4NTFHWjBITmo4VnZwdEM4WGdVTElGMFBBVlptWEJZUGlrUCIsCiAgICAgICJjcnYiOiAiUC0zODQiLAogICAgICAia3R5IjogIkVDIgogICAgfSwKICAgICJpZCI6IDE3ODk3OSwKICAgICJyZXNvdXJjZSI6ICJyZWciCiAgfQp9Cg==
```

To generate this, you can use `example/getusersecret.sh -e your@email.com -s acme-staging.api.letsencrypt.org`. 
This one obviously uses staging letsencrypt servers so you need to change to production one (acme-v01.api.letsencrypt.org) when going prod.

At this point you can create a service and deployment in your namespace from `example/deployment.yaml` and `example/service.yaml`. 
Remember to update --acme-email and --acme-server to their correct values in the deployment.

You now have kube-acme ready to handle your certificates in the namespace they are provisioned in.

### Setting ingress to use ACME secrets

Assuming you have completed the initial setup described above, you can now proceed with defining acme enabled ingress. 
Start by creating a new secret that your ingress will reference, and make sure the secret is acme enabled

```
apiVersion: v1
kind: Secret
metadata:
  name: some.domain.tld-acmetls
  labels:
    acme-managed: 'true'
type: Opaque
data:
```

> Remember this should be done once, and once only. If you apply this secret again you may end up wiping a valid certificate.

Before you proceed with creating ingresses to handle your incoming traffic it is preferable that you alredy point 
the domain name to the ingress controller IP address. In some cases (ie. when each ingress gets a separate IP 
after it is created) this will not be possible. In such situations you need to create the ingress, point the domain name 
to the new assigned IP and then modify ingress (ie. by adding/changing a custom label) so that `kube-acme` is forced 
to attempt certificate generation again. Before you create the actual TLS enabled ingress, you need an HTTP ingress 
to respond to acme-challenge.

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: some.domain.tld-acme
spec:
  rules:
  - host: some.domain.tld
    http:
      paths:
      - path: /
        backend:
          serviceName: kube-acme
          servicePort: 80
```

This will route all traffic for this domain on using http:// to kube-acme service. 
Apart of serving the `/.well-known/acme-challenge/` to respond to the challenge requests, 
`kube-acme` redirects all http:// traffic to https:// so it can reside on `/` path 
and make sure all non-acme-challenge traffic goes via encrypted channel. 
With this in place an acme enabled tls ingress can be created

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: echo
  labels:
    acme-tls: "true"
spec:
  tls:
  - secretName: some.domain.tld-acmetls
    hosts:
    - some.domain.tld
  rules:
  - host: some.domain.tld
    http:
      paths:
      - path: /echo
        backend:
          serviceName: echo
          servicePort: 8080
```

The example above assumes you have `example/echo.service.yml` and `example/echo.deployment.yml` in your namespace
to respond with request echo for testing. After a short while you can verify if certificate was created
with `kubectl get secret some.domain.tld-acmetls` which should now contain data fields for _acme.certificate-resource_,
_tls.crt_ and _tls.key_. To debug the certificate issuing you might want to use `kubectl logs -c monitor <your_acme_pod>`
