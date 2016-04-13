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

## Usage

* _coming soon_
