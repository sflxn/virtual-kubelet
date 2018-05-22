package storage

import (
	"github.com/virtual-kubelet/virtual-kubelet/vkubelet"
	clientset "k8s.io/client-go/kubernetes"
)

type StorageController interface {
	Run()
	Stop()
}

type storageHandler struct {
	classProvider vkubelet.StorageClassProvider
	stop          chan struct{}
	kubeClient    clientset.Interface
}

func NewStorageHandler(kubeClient clientset.Interface) StorageController {
	return &storageHandler{
		kubeClient: kubeClient,
		stop:       make(chan struct{}, 1),
	}
}

func (h *storageHandler) Run() {

}

func (h *storageHandler) Stop() {

}

func (h *storageHandler) syncLoop() {
	select {
	case <- h.stop:
		break

	}
}
