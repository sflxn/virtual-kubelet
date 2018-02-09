package vic

import (
	"golang.org/x/net/context"

	vicproxy "github.com/vmware/vic/lib/apiservers/engine/proxy"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/apiservers/portlayer/models"
	"github.com/vmware/vic/pkg/trace"

	"fmt"

	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/proxy"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/cache"
)

type VicProvider struct {
	resourceManager *manager.ResourceManager
	nodeName        string
	os              string
	portlayerAddr   string
	podCount        int
	client          *client.PortLayer
	imageStore      proxy.ImageStore
	podProxy        proxy.PodProxy
	systemProxy		vicproxy.VicSystemProxy
}


func NewVicProvider(configFile string, rm *manager.ResourceManager, nodeName, operatingSystem string) (*VicProvider, error) {
	config := NewVicConfig(configFile)

	plClient := vicproxy.NewPortLayerClient(config.PortlayerAddr)
	i, err := proxy.NewImageStore(plClient)
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize the image store")
	}

	p := VicProvider{
		client:          plClient,
		resourceManager: rm,
		systemProxy:	vicproxy.NewSystemProxy(plClient),
	}

	p.imageStore = i
	p.podProxy = proxy.NewPodProxy(plClient, i, cache.NewVicPodCache())

	return &p, nil
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

	op.Info("pod spec = %#v", pod.Spec)

	err := v.podProxy.CreatePod(op.Context, pod)
	if err != nil {
		return err
	}

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
		op.Errorf(err)

		return nil, err
	}

	return nil, nil
}

// GetContainerLogs retrieves the logs of a container by name from the provider.
func (v *VicProvider) GetContainerLogs(namespace, podName, containerName string, tail int) (string, error) {
	return "", nil
}

// GetPodStatus retrieves the status of a pod by name from the provider.
func (v *VicProvider) GetPodStatus(namespace, name string) (*v1.PodStatus, error) {
	return nil, nil
}

// GetPods retrieves a list of all pods running on the provider (can be cached).
func (v *VicProvider) GetPods() ([]*v1.Pod, error) {
	return []*v1.Pod{}, nil
}

// Capacity returns a resource list with the capacity constraints of the provider.
func (v *VicProvider) Capacity() v1.ResourceList {
	op := trace.NewOperation(context.Background(), "VicProvider.Capacity")
	defer trace.End(trace.Begin("", op))

	if v.systemProxy == nil {
		err := NilProxy("VicProvider.Capacity", "SystemProxy")
		op.Errorf(err)

		return err
	}

	info, err := v.systemProxy.VCHInfo(context.Background())
	if err != nil {
		return v1.ResourceList{}
	}

	return KubeResourcesFromVchInfo(info)
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
	return []v1.NodeAddress{}
}

// NodeDaemonEndpoints returns NodeDaemonEndpoints for the node status
// within Kubernetes.
func (v *VicProvider) NodeDaemonEndpoints() *v1.NodeDaemonEndpoints {
	return nil
}

// OperatingSystem returns the operating system the provider is for.
func (v *VicProvider) OperatingSystem() string {
	return "Photon OS"
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