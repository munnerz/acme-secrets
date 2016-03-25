package main

import (
	"github.com/golang/glog"
	"github.com/munnerz/acme-secrets/cmd/monitor"
	"github.com/munnerz/acme-secrets/cmd/serve"
	"github.com/namsral/flag"
)

var (
	monitorF = flag.Bool("monitor", false, "monitor api server for new ingress resources")
	serveF   = flag.Bool("serve", false, "serve secret challenges to the acme server")
	proxyURL = flag.String("proxyURL", "", "URL to proxy connections to the apiserver")
)

func main() {
	flag.Parse()

	if !*monitorF && !*serveF {
		glog.Fatalf("Either -monitor or -serve must be used")
	}

	if *monitorF {
		monitor.Main(proxyURL)
	} else {
		serve.Main(proxyURL)
	}

}
