// Copyright 2018 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"context"
	"fmt"
	"sync"

	"github.com/vmware/vic/pkg/trace"

	vicpod "github.com/virtual-kubelet/virtual-kubelet/providers/vic/pod"
)

type PodCache interface {
	Get(ctx context.Context, namespace, name string) (*vicpod.VicPod, error)
	GetAll(ctx context.Context) []*vicpod.VicPod
	Add(ctx context.Context, name string, pod *vicpod.VicPod) error
	Delete(ctx context.Context, name string)
}

type VicPodCache struct {
	cache map[string]*vicpod.VicPod
	lock  sync.Mutex
}

func NewVicPodCache() PodCache {
	v := &VicPodCache{}

	v.cache = make(map[string]*vicpod.VicPod, 0)

	return v
}

func (v *VicPodCache) Rehydrate(ctx context.Context) error {
	return nil
}

func (v *VicPodCache) Get(ctx context.Context, namespace, name string) (*vicpod.VicPod, error) {
	op := trace.FromContext(ctx, "Get")
	defer trace.End(trace.Begin(name, op))

	//vicName := vicpod.VicName(namespace, name)
	//pod, ok := v.cache[vicName]
	pod, ok := v.cache[name]
	if !ok {
		err := fmt.Errorf("Pod %s not found in cache", name)

		op.Info(err)
		return nil, err
	}

	return pod, nil
}

func (v *VicPodCache) GetAll(ctx context.Context) []*vicpod.VicPod {
	op := trace.FromContext(ctx, "GetAll")
	defer trace.End(trace.Begin("", op))
	defer v.lock.Unlock()
	v.lock.Lock()

	list := make([]*vicpod.VicPod, 0)

	for _, vp := range v.cache {
		list = append(list, vp)
	}

	return list
}

func (v *VicPodCache) Add(ctx context.Context, name string, pod *vicpod.VicPod) error {
	op := trace.FromContext(ctx, "Add")
	defer trace.End(trace.Begin(name, op))
	defer v.lock.Unlock()
	v.lock.Lock()

	_, ok := v.cache[name]
	if ok {
		err := fmt.Errorf("Pod %s already cached.  Duplicate pod.", name)

		op.Error(err)
		return err
	}

	v.cache[name] = pod
	return nil
}

func (v *VicPodCache) Delete(ctx context.Context, name string) {
	op := trace.FromContext(ctx, "Delete")
	defer trace.End(trace.Begin(name, op))
	defer v.lock.Unlock()
	v.lock.Lock()

	delete(v.cache, name)
}
