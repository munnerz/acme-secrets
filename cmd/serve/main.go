package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/gorilla/mux"

	"k8s.io/kubernetes/pkg/api"
	client "k8s.io/kubernetes/pkg/client/unversioned"
)

var (
	proxyURL   = flag.String("proxyURL", "", "URL to proxy connections to the apiserver")
	listenAddr = flag.String("listenAddr", "0.0.0.0:12000", "the address to listen on for incoming http requests")

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

	r := mux.NewRouter()

	r.HandleFunc("/.well-known/acme-challenge/{key}", HandleChallenge)

	glog.Fatalln(http.ListenAndServe(fmt.Sprintf("%s", *listenAddr), r))
}

func HandleChallenge(w http.ResponseWriter, r *http.Request) {
	// TODO: Make use of key in request URI

	glog.Errorf("Req from: %s", r.Host)
	res, err := kubeClient.RESTClient.Get().
		Namespace("acme").
		Resource("secrets").
		Name(fmt.Sprintf("%s-acme", r.Host)).
		Do().
		Get()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	if sec, ok := res.(*api.Secret); !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	} else {
		if challenge, ok := sec.Data["acme-auth"]; !ok {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		} else {
			w.Write(challenge)
		}
	}
}
