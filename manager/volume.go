package manager

import (
	"fmt"
	"log"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// This duration correspond to the regular kubelet volume manager's desired state of the world sync loop durations
	podVolumeUpdateDuration time.Duration = 100 * time.Microsecond
)

type PodVolume struct {
	Processed bool
	Pod       *v1.Pod
	Volume    *v1.Volume
	PV        *v1.PersistentVolume
	ReadOnly  bool
}

// Information from the provider
type ProviderStorageClass struct {
	StorageClass string
	PluginName   string
}


//*************************************************************************************************
// Provider storage class support calls
//*************************************************************************************************
func (rm *ResourceManager) AddSupportedStorageClass(storageClass, pluginName string) {
	rm.storageProvider[storageClass] = &ProviderStorageClass{
		StorageClass: storageClass,
		PluginName: pluginName,
	}
}

//*************************************************************************************************
// VolumeManger
//*************************************************************************************************
func (rm *ResourceManager) GetVolumeMap() map[string]PodVolume {
	return rm.volumeMap
}

func (rm *ResourceManager) volumeSyncLoop() func() {
	return func() {
		for _, pod := range rm.GetPods() {
			// Find new pods known to kubernetes whose volumes we have not yet processed.
			podID := string(pod.UID)
			if p, _ := rm.pods[podID]; p == nil {
				err := rm.processNewPodVolume(pod)
				if err != nil {
					// What are we doing for logging?
				}
			}
		}
	}
}

func (rm *ResourceManager) processNewPodVolume(p *v1.Pod) error {
	// Create a map of filesystem and block volumes for every container in the pod
	mounts, devices := rm.createVolumeMap(p)

	for _, volume := range p.Spec.Volumes {
		if name := volume.VolumeSource.PersistentVolumeClaim.ClaimName; name != "" {
			pv, pvc, sp, err := rm.validateVolume(p.Namespace, name, mounts, devices)
			if err != nil || pv == nil || pvc == nil {
				e := fmt.Errorf("Mismatch between PV and PVC %s: %v", name, err)
				log.Printf(e.Error())
				return e
			}

			// Map pod to the volume.  This mapping is eventually given to the provider
			volCopy := volume.DeepCopy()
			rm.mapPodToVolume(volCopy, pv, sp, p, volume.PersistentVolumeClaim.ReadOnly)
		}
	}

	return nil
}

func (rm *ResourceManager) validateVolume(namespace, claimName string, mounts, devices map[string]bool) (*v1.PersistentVolume, *v1.PersistentVolumeClaim, *ProviderStorageClass, error) {
	// Validate the volume with the PVC and PV from the api server
	pvc, err := rm.getPVC(namespace, claimName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to fetch PVC for claim %s: %v", claimName, err)
	}

	pv, err := rm.getPV(pvc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to get PV related to claim %s: %v", claimName, err)
	}

	//validate the PV's volume mode matches the container's map from the pod spec
	volumeMode := *pv.Spec.VolumeMode
	if mounts[pv.Name] && volumeMode != v1.PersistentVolumeFilesystem {
		return nil, nil, nil, fmt.Errorf("Pod's container expected volume %s to be a filesystem volume but PV's is not", pv.Name)
	}

	if devices[pv.Name] && volumeMode != v1.PersistentVolumeBlock {
		return nil, nil, nil, fmt.Errorf("Pod's container expected volume %s to be a block device but PV's is not", pv.Name)
	}

	// Does the provider support this PVC's storage class?
	sp, ok := rm.storageProvider[*pvc.Spec.StorageClassName]
	if !ok {
		return nil, nil, nil, fmt.Errorf("PVC expects storage class %s but the virtual kubelet provider does not support this class", *pvc.Spec.StorageClassName)
	}

	return pv, pvc, sp, nil
}

func (rm *ResourceManager) mapPodToVolume(volume *v1.Volume, pv *v1.PersistentVolume, sp *ProviderStorageClass, p *v1.Pod, readonly bool) {
	uniqueName := fmt.Sprintf("%s/%s-%s", sp.PluginName, p.UID, volume.Name)

	rm.volumeMap[uniqueName] = PodVolume{
		Volume:   volume,
		PV:       pv,
		Pod:      p,
		ReadOnly: readonly,
	}
}

func (rm *ResourceManager) createVolumeMap(p *v1.Pod) (map[string]bool, map[string]bool) {
	var mounts, devices map[string]bool
	for _, c := range p.Spec.Containers {
		for _, v := range c.VolumeMounts {
			mounts[v.Name] = true
		}

		for _, d := range c.VolumeDevices {
			devices[d.Name] = true
		}
	}

	return mounts, devices
}

func (rm *ResourceManager) getPVC(namespace string, claimName string) (*v1.PersistentVolumeClaim, error) {
	pvc, err := rm.k8sClient.CoreV1().PersistentVolumeClaims(namespace).Get(claimName, metav1.GetOptions{})
	if err != nil || pvc == nil {
		return nil, err
	}

	if pvc.ObjectMeta.DeletionTimestamp != nil {
		return nil, fmt.Errorf("PVC %s/%s is being deleted",	namespace, claimName)
	}

	if pvc.Status.Phase != v1.ClaimBound || pvc.Spec.VolumeName == "" {
		return nil, fmt.Errorf("PVC %s/%s has non-bound phase (%q) or empty pvc.Spec.VolumeName (%q)",
			namespace,
			claimName,
			pvc.Status.Phase,
			pvc.Spec.VolumeName)
	}

	return pvc, nil
}

func (rm *ResourceManager) getPV(pvc *v1.PersistentVolumeClaim) (*v1.PersistentVolume, error) {
	pv, err := rm.k8sClient.CoreV1().PersistentVolumes().Get(pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv == nil {
		return nil, err
	}

	if pv.Spec.ClaimRef == nil {
		return nil, fmt.Errorf("Retrieved PV for PVC %s but the PV's claim is nil", pvc.Name)
	}

	if pv.Spec.ClaimRef.UID != pvc.UID {
		return nil, fmt.Errorf("The PVC's UID (%s) do not match the PV's claim UID (%s)", pvc.UID, pv.Spec.ClaimRef.UID)
	}

	return pv, nil
}
