package vic

import (
	"github.com/vmware/vic/lib/apiservers/engine/proxy"

	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"k8s.io/api/core/v1"
	"github.com/kubernetes/contrib/diurnal/Godeps/_workspace/src/golang.org/x/net/context"
)

type VicProvider struct {
	resourceManager    *manager.ResourceManager
	nodeName			string
	os					string
	portlayerAddr		string
	podCount			int
}

func NewVicProvider(config string, rm *manager.ResourceManager, nodeName, operatingSystem string) (*VicProvider, error) {
	p := VicProvider{
		resourceManager: rm,
	}
	return &p, nil
}

// CreatePod takes a Kubernetes Pod and deploys it within the provider.
func (v *VicProvider) CreatePod(pod *v1.Pod) error {
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
	client := proxy.NewPortLayerClient(v.portlayerAddr)
	systemProxy := proxy.NewSystemProxy(client)

	vchInfo, err := systemProxy.VCHInfo(context.Background())
	if err != nil {
		return v1.ResourceList{}
	}

	return v1.ResourceList{
		"cpu":    resource.MustParse(v.cpu),
		"memory": resource.MustParse(v.memory),
		"pods":   resource.MustParse(v.pods),
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
