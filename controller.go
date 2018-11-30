package main

import (
	"fmt"
	"time"

	"github.com/golang/glog"

	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/certificates/v1beta1"
	clientset "k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Controller represents a controller used for approving csrs
type Controller struct {
	kubeClient clientset.Interface

	csrLister  listers.CertificateSigningRequestLister
	csrsSynced cache.InformerSynced

	handler func(*certificates.CertificateSigningRequest) error

	queue workqueue.RateLimitingInterface
}

// NewController creates a new csr approving controller
func NewController(
	client clientset.Interface,
	informer informers.CertificateSigningRequestInformer,
	handler func(*certificates.CertificateSigningRequest) error,
) *Controller {

	cc := &Controller{
		kubeClient: client,
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "csr"),
		handler:    handler,
	}

	// Manage the addition/update of certificate requests
	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			glog.V(4).Infof("Adding certificate request %s", csr.Name)
			cc.enqueue(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			glog.V(4).Infof("Updating certificate request %s", oldCSR.Name)
			cc.enqueue(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					glog.V(2).Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			glog.V(4).Infof("Deleting certificate request %s", csr.Name)
			cc.enqueue(obj)
		},
	})
	cc.csrLister = informer.Lister()
	cc.csrsSynced = informer.Informer().HasSynced
	return cc
}

// Run the controller workers.
func (cc *Controller) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer cc.queue.ShutDown()

	glog.Infof("Starting certificate controller")
	defer glog.Infof("Shutting down certificate controller")

	if !cache.WaitForCacheSync(stopCh, cc.csrsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(cc.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (cc *Controller) runWorker() {
	for cc.processNextWorkItem() {
	}
}

func (cc *Controller) processNextWorkItem() bool {
	cKey, quit := cc.queue.Get()
	if quit {
		return false
	}

	defer cc.queue.Done(cKey)

	if err := cc.sync(cKey.(string)); err != nil {
		cc.queue.AddRateLimited(cKey)
		utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", cKey, err))

		return true
	}

	cc.queue.Forget(cKey)
	return true

}

func (cc *Controller) enqueue(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	cc.queue.Add(key)
}

func (cc *Controller) sync(key string) error {
	startTime := time.Now()

	defer func() {
		glog.V(4).Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()

	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		glog.V(3).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if csr.Status.Certificate != nil {
		// no need to do anything because it already has a cert
		return nil
	}

	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()

	return cc.handler(csr)
}
