#!/bin/bash

if [ $(which wget | wc -l) -eq 0 ]; then echo 'Missing "wget". Aborting'; exit 1; fi
if [ $(which jq | wc -l) -eq 0 ]; then echo 'Missing "jq". Aborting'; exit 1; fi
if [ $(which base64 | wc -l) -eq 0 ]; then echo 'Missing "base64". Aborting'; exit 1; fi
if [ $(which xz | wc -l) -eq 0 ]; then echo 'Missing "xz". Aborting'; exit 1; fi

SERVER="acme-staging.api.letsencrypt.org"
EMAIL="test@test.com"

while [[ $# > 1 ]]
do
  key="$1"
  case $key in
    -e|--email) EMAIL="$2"; shift ;;
    -s|--server) SERVER="$2"; shift ;;
  esac
  shift
done

echo
echo "### Ready to register user with $EMAIL on $SERVER (Hit any key to proceed or Ctrl+C to cancel)"
echo
read
echo "Processing..."

TMPDIR="$(pwd)/.kube-acme-tmp/"
rm -rf $TMPDIR

wget https://github.com/xenolf/lego/releases/download/v0.3.0/lego_linux_amd64.tar.xz -c -P $TMPDIR -q
tar -C $TMPDIR -xf $TMPDIR/lego_linux_amd64.tar.xz
/tmp/lego/lego -s "https://$SERVER/directory" -m "$EMAIL" -a --path $TMPDIR run
echo
echo "###  "
echo "###  Below you can find your private information for $EMAIL on $SERVER"
echo "###  "
echo
echo "### Private key :"
echo
cat $TMPDIR/accounts/$SERVER/$EMAIL/keys/$EMAIL.key
echo
echo "### Account settings json :"
echo
cat $TMPDIR/accounts/$SERVER/$EMAIL/account.json | jq '.registration'
echo
echo
echo "### Kubernetes acme-secret template :"
echo
echo "
apiVersion: v1
kind: Secret
metadata:
  name: kube-acme-user
type: Opaque
data:
  private.key: $(cat $TMPDIR/accounts/$SERVER/$EMAIL/keys/$EMAIL.key | base64 -w0)
  acme-reg.json: $(cat $TMPDIR/accounts/$SERVER/$EMAIL/account.json | jq '.registration' | base64 -w0)
"
rm -rf $TMPDIR
echo
echo "###  "
echo "###  Make sure you put this information in a safe place"
echo "###  it is alredy deleted from temporary storage on your account"
echo "###  so there is no other way to secure this other than to store it in a safe place now"
echo "###  "
echo
