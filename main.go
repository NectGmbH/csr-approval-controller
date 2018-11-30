package main

import (
	"flag"
	"time"

	"github.com/golang/glog"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig, masterURL, cn, org, dns, email, ip, groups, username string

	flag.StringVar(&cn, "cn", "", "Regex filter for common name of the csr")
	flag.StringVar(&org, "org", "", "Regex filter for organization of the csr")
	flag.StringVar(&username, "username", "", "Regex filter for username of the csr")
	flag.StringVar(&dns, "dns", "", "Regex filter for dns addresses of the csr (joined by ,)")
	flag.StringVar(&email, "email", "", "Regex filter for email addresses of the csr (joined by ,)")
	flag.StringVar(&ip, "ip", "", "Regex filter for ip addresses of the csr (joined by ,)")
	flag.StringVar(&groups, "groups", "", "Regex filter for groups of the csr (joined by ,)")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.Parse()

	if cn == "" && org == "" && username == "" && dns == "" && email == "" && ip == "" && groups == "" {
		glog.Fatalf("Didn't specify any filter, aborting.")
	}

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClient, time.Second*30)
	approver := NewApprover(kubeClient, cn, org, dns, email, ip, groups, username)

	controller := NewController(
		kubeClient,
		kubeInformerFactory.Certificates().V1beta1().CertificateSigningRequests(),
		approver.Handle,
	)

	stopCh := make(chan struct{})
	defer close(stopCh)

	kubeInformerFactory.Start(stopCh)
	controller.Run(2, stopCh)
}
