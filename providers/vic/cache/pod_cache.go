package cache

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/api/core/v1"

	"github.com/vmware/vic/pkg/trace"

	vicpod "github.com/virtual-kubelet/virtual-kubelet/providers/vic/pod"
)

type PodCache interface {
	Get(ctx context.Context, namespace, name string) (*v1.Pod, error)
	GetAll(ctx context.Context) []*v1.Pod
	Add(ctx context.Context, vicName string, pod *v1.Pod) error
	Delete(ctx context.Context, vicName string)
}

type VicPodCache struct {
	cache map[string]*v1.Pod
	lock  sync.Mutex
}

func NewVicPodCache() PodCache {
	v := &VicPodCache{}

	v.cache = make(map[string]*v1.Pod, 0)

	return v
}

func (v *VicPodCache) Rehydrate(ctx context.Context) error {
	return nil
}

func (v *VicPodCache) Get(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	op := trace.FromContext(ctx, "Get")
	defer trace.End(trace.Begin(name, op))

	vicName := vicpod.VicName(namespace, name)
	pod, ok := v.cache[vicName]
	if !ok {
		err := fmt.Errorf("Pod %s not found in cache", name)

		op.Info(err)
		return nil, err
	}

	return pod, nil
}

func (v *VicPodCache) GetAll(ctx context.Context) []*v1.Pod {
	op := trace.FromContext(ctx, "GetAll")
	defer trace.End(trace.Begin("", op))

	list := make([]*v1.Pod, 0)

	for _, pod := range v.cache {
		list = append(list, pod)
	}

	return list
}

func (v *VicPodCache) Add(ctx context.Context, vicName string, pod *v1.Pod) error {
	op := trace.FromContext(ctx, "Add")
	defer trace.End(trace.Begin(pod.Name, op))
	defer v.lock.Unlock()
	v.lock.Lock()

	_, ok := v.cache[vicName]
	if ok {
		err := fmt.Errorf("Pod %s already cached.  Duplicate pod.", pod.Name)

		op.Error(err)
		return err
	}

	v.cache[vicName] = pod
	return nil
}

func (v *VicPodCache) Delete(ctx context.Context, vicName string) {
	op := trace.FromContext(ctx, "Delete")
	defer trace.End(trace.Begin(vicName, op))
	defer v.lock.Unlock()
	v.lock.Lock()

	delete(v.cache, vicName)
}
