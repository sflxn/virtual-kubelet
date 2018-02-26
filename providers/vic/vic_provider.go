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

package vic

import (
	"fmt"
	"os"
	"path"
	"time"

	"golang.org/x/net/context"

	log "github.com/Sirupsen/logrus"

	vicproxy "github.com/vmware/vic/lib/apiservers/engine/proxy"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/apiservers/portlayer/models"
	"github.com/vmware/vic/lib/constants"
	"github.com/vmware/vic/pkg/dio"
	viclog "github.com/vmware/vic/pkg/log"
	"github.com/vmware/vic/pkg/trace"

	"syscall"

	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/cache"
	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/proxy"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VicProvider struct {
	resourceManager *manager.ResourceManager
	nodeName        string
	os              string
	podCount        int
	config          VicConfig
	podCache        cache.PodCache

	client      *client.PortLayer
	imageStore  proxy.ImageStore
	podProxy    proxy.PodProxy
	systemProxy vicproxy.VicSystemProxy
}

const (
	RunningInVCH = false
	LogFilename  = "virtual-kubelet"

	// PanicLevel level, highest level of severity. Logs and then calls panic with the
	// message passed to Debug, Info, ...
	PanicLevel uint8 = iota
	// FatalLevel level. Logs and then calls `os.Exit(1)`. It will exit even if the
	// logging level is set to Panic.
	FatalLevel
	// ErrorLevel level. Logs. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel
	// InfoLevel level. General operational entries about what's going on inside the
	// application.
	InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel
)

func NewVicProvider(configFile string, rm *manager.ResourceManager, nodeName, operatingSystem string) (*VicProvider, error) {
	initLogger()

	op := trace.NewOperation(context.Background(), "VicProvider creation: config - %s", configFile)
	defer trace.End(trace.Begin("", op))

	config := NewVicConfig(op, configFile)

	plClient := vicproxy.NewPortLayerClient(config.PortlayerAddr)
	i, err := proxy.NewImageStore(plClient, config.PortlayerAddr)
	if err != nil {
		msg := "Couldn't initialize the image store"
		op.Error(msg)
		return nil, fmt.Errorf(msg)
	}

	p := VicProvider{
		config:          config,
		nodeName:        nodeName,
		os:              operatingSystem,
		podCache:        cache.NewVicPodCache(),
		client:          plClient,
		resourceManager: rm,
		systemProxy:     vicproxy.NewSystemProxy(plClient),
	}

	p.imageStore = i
	p.podProxy = proxy.NewPodProxy(plClient, config.PersonaAddr, config.PortlayerAddr, i, p.podCache)

	return &p, nil
}

func initLogger() {
	logPath := path.Join("", constants.DefaultLogDir, LogFilename+".log")

	os.MkdirAll(constants.DefaultLogDir, 0755)
	// #nosec: Expect file permissions to be 0600 or less
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_SYNC|syscall.O_NOCTTY, 0644)
	if err != nil {
		detail := fmt.Sprintf("failed to open file for VIC's virtual kubelet provider log: %s", err)
		log.Error(detail)
	}

	// use multi-writer so it goes to both screen and session log
	writer := dio.MultiWriter(f, os.Stdout)

	logcfg := viclog.NewLoggingConfig()

	logcfg.SetLogLevel(DebugLevel)
	trace.SetLoggerLevel(DebugLevel)
	trace.Logger.Out = writer

	err = viclog.Init(logcfg)
	if err != nil {
		return
	}

	trace.InitLogger(logcfg)
}

// CreatePod takes a Kubernetes Pod and deploys it within the provider.
func (v *VicProvider) CreatePod(pod *v1.Pod) error {
	op := trace.NewOperation(context.Background(), "CreatePod - %s", pod.Name)
	defer trace.End(trace.Begin(pod.Name, op))

	if v.podProxy == nil {
		err := NilProxy("VicProvider.CreatePod", "PodProxy")
		op.Error(err)

		return err
	}

	op.Infof("%s's pod spec = %#v", pod.Name, pod.Spec)

	err := v.podProxy.CreatePod(op.Context, pod.Name, pod)
	if err != nil {
		return err
	}

	op.Infof("** pod created ok")
	return nil
}

// UpdatePod takes a Kubernetes Pod and updates it within the provider.
func (v *VicProvider) UpdatePod(pod *v1.Pod) error {
	return nil
}

// DeletePod takes a Kubernetes Pod and deletes it from the provider.
func (v *VicProvider) DeletePod(pod *v1.Pod) error {
	return nil
}

// GetPod retrieves a pod by name from the provider (can be cached).
func (v *VicProvider) GetPod(namespace, name string) (*v1.Pod, error) {
	op := trace.NewOperation(context.Background(), "GetPod - %s", name)
	defer trace.End(trace.Begin(name, op))

	if v.podProxy == nil {
		err := NilProxy("VicProvider.GetPod", "PodProxy")
		op.Error(err)

		return nil, err
	}

	// Look for the pod in our cache of running pods
	pod, err := v.podCache.Get(op.Context, namespace, name)
	if err != nil {
		return nil, err
	}

	return pod, nil
}

// GetContainerLogs retrieves the logs of a container by name from the provider.
func (v *VicProvider) GetContainerLogs(namespace, podName, containerName string, tail int) (string, error) {
	op := trace.NewOperation(context.Background(), "GetContainerLogs - pod[%s], container[%s]", podName, containerName)
	defer trace.End(trace.Begin("", op))

	return "", nil
}

// GetPodStatus retrieves the status of a pod by name from the provider.
// This function needs to return a status or the reconcile loop will stop running.
func (v *VicProvider) GetPodStatus(namespace, name string) (*v1.PodStatus, error) {
	op := trace.NewOperation(context.Background(), "GetPodStatus - pod[%s], namespace", name, namespace)
	defer trace.End(trace.Begin("GetPodStatus", op))

	now := metav1.NewTime(time.Now())

	status := &v1.PodStatus{
		Phase:     v1.PodRunning,
		HostIP:    "1.2.3.4",
		PodIP:     "5.6.7.8",
		StartTime: &now,
		Conditions: []v1.PodCondition{
			{
				Type:   v1.PodInitialized,
				Status: v1.ConditionTrue,
			},
			{
				Type:   v1.PodReady,
				Status: v1.ConditionTrue,
			},
			{
				Type:   v1.PodScheduled,
				Status: v1.ConditionTrue,
			},
		},
	}

	pod, err := v.GetPod(namespace, name)
	if err != nil {
		return status, err
	}

	for _, container := range pod.Spec.Containers {
		status.ContainerStatuses = append(status.ContainerStatuses, v1.ContainerStatus{
			Name:         container.Name,
			Image:        container.Image,
			Ready:        true,
			RestartCount: 0,
			State: v1.ContainerState{
				Running: &v1.ContainerStateRunning{
					StartedAt: now,
				},
			},
		})
	}

	return status, nil
}

// GetPods retrieves a list of all pods running on the provider (can be cached).
func (v *VicProvider) GetPods() ([]*v1.Pod, error) {
	op := trace.NewOperation(context.Background(), "GetPods")
	defer trace.End(trace.Begin("GetPods", op))

	op.Info("** GetPods")
	if v.podProxy == nil {
		err := NilProxy("VicProvider.GetPods", "PodProxy")
		op.Error(err)

		return nil, err
	}

	allPods := v.podCache.GetAll(op.Context)

	return allPods, nil
}

// Capacity returns a resource list with the capacity constraints of the provider.
func (v *VicProvider) Capacity() v1.ResourceList {
	op := trace.NewOperation(context.Background(), "VicProvider.Capacity")
	defer trace.End(trace.Begin("", op))

	if RunningInVCH {
		if v.systemProxy == nil {
			err := NilProxy("VicProvider.Capacity", "SystemProxy")
			op.Error(err)

			return v1.ResourceList{}
		}

		info, err := v.systemProxy.VCHInfo(context.Background())
		if err != nil {
			op.Errorf("VicProvider.Capacity failed to get vchinfo: %s", err.Error())
			return v1.ResourceList{}
		}

		return KubeResourcesFromVchInfo(info)
	} else {
		// Return fake data
		return v1.ResourceList{
			"cpu":    resource.MustParse("20"),
			"memory": resource.MustParse("100Gi"),
			"pods":   resource.MustParse("20"),
		}
	}
}

// NodeConditions returns a list of conditions (Ready, OutOfDisk, etc), which is polled periodically to update the node status
// within Kubernetes.
func (v *VicProvider) NodeConditions() []v1.NodeCondition {
	// TODO: Make these dynamic and augment with custom ACI specific conditions of interest
	return []v1.NodeCondition{
		{
			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: metav1.Now(),
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",
		},
		{
			Type:               "OutOfDisk",
			Status:             v1.ConditionFalse,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: metav1.Now(),
			Reason:             "KubeletHasSufficientDisk",
			Message:            "kubelet has sufficient disk space available",
		},
		{
			Type:               "MemoryPressure",
			Status:             v1.ConditionFalse,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: metav1.Now(),
			Reason:             "KubeletHasSufficientMemory",
			Message:            "kubelet has sufficient memory available",
		},
		{
			Type:               "DiskPressure",
			Status:             v1.ConditionFalse,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: metav1.Now(),
			Reason:             "KubeletHasNoDiskPressure",
			Message:            "kubelet has no disk pressure",
		},
		{
			Type:               "NetworkUnavailable",
			Status:             v1.ConditionFalse,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: metav1.Now(),
			Reason:             "RouteCreated",
			Message:            "RouteController created a route",
		},
	}
}

// NodeAddresses returns a list of addresses for the node status
// within Kubernetes.
func (v *VicProvider) NodeAddresses() []v1.NodeAddress {
	return nil
}

// NodeDaemonEndpoints returns NodeDaemonEndpoints for the node status
// within Kubernetes.
func (v *VicProvider) NodeDaemonEndpoints() *v1.NodeDaemonEndpoints {
	return &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{
			Port: 80,
		},
	}
}

// OperatingSystem returns the operating system the provider is for.
func (v *VicProvider) OperatingSystem() string {
	return v.os
}

//------------------------------------
// Utility Functions
//------------------------------------

// KubeResourcesFromVchInfo returns a K8s node resource list, given the VCHInfo
func KubeResourcesFromVchInfo(info *models.VCHInfo) v1.ResourceList {
	var nr v1.ResourceList

	// translate CPU resources.  K8s wants cores.  We have virtual cores based on mhz.
	cpuQ := resource.Quantity{}
	cpuQ.Set(info.CPUMhz)
	nr[v1.ResourceCPU] = cpuQ

	// translate memory resources.  K8s wants bytes.
	memQ := resource.Quantity{}
	memQ.Set(info.Memory)
	nr[v1.ResourceMemory] = memQ

	// translate storage and nvida gpu info
	q := resource.Quantity{}
	q.Set(0)
	nr[v1.ResourceStorage] = q
	nr[v1.ResourceEphemeralStorage] = q
	nr[v1.ResourceNvidiaGPU] = q

	// Get pod count
	nr[v1.ResourcePods] = q

	return nr
}

func NilProxy(caller, proxyName string) error {
	return fmt.Errorf("%s: %s not valid", caller, proxyName)
}
