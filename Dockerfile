FROM scratch

ADD acme-secrets /acme-secrets

ENTRYPOINT ["/acme-secrets]