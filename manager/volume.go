package manager

import (
	"fmt"
	"time"

	"k8s.io/api/core/v1"
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

func (rm *ResourceManager) volumeSyncLoop() {
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

func (rm *ResourceManager) processNewPodVolume(p *v1.Pod) {
	// Create a map of filesystem and block volumes for every container in the pod
	mounts, devices := rm.createVolumeMap(p)

	for _, volume := range p.Spec.Volumes {
		if name := volume.VolumeSource.PersistentVolumeClaim; name != nil {
			pv, pvc, sp, err := rm.validateVolume(p.Namespace, name, mounts, devices)
			if err != nil || pv == nil || pvc == nil {
				// Log error
			}

			// Map pod to the volume.  This mapping is eventually given to the provider
			volCopy := volume.DeepCopy()
			rm.mapPodToVolume(volCopy, pv, sp, p, volume.PersistentVolumeClaim.ReadOnly)
		}
	}
}

func (rm *ResourceManager) validateVolume(namespace, claimName string, mounts, devices map[string]bool) (*v1.PersistentVolume, *v1.PersistentVolumeClaim, *ProviderStorageClass, error) {
	// Validate the volume with the PVC and PV from the api server
	pvc, err := rm.getPVC(namespace, claimName)
	if err != nil {
		// Log something
	}

	pv, err := rm.getPV(pvc)
	if err != nil {
		// Log something
	}

	//validate the PV's volume mode matches the container's map from the pod spec
	volumeMode := pv.Spec.VolumeMode
	if mounts[pv.Name] && volumeMode != v1.PersistentVolumeFilesystem {
		// Log an error
	}

	if devices[pv.Name] && volumeMode != v1.PersistentVolumeBlock {
		// Log an error
	}

	// Does the provider support this PVC's storage class?
	if sp, ok := rm.storageProvider[pvc.Spec.StorageClassName]; !ok {
		// Log an error
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
		// Log something
	}

	if pvc.ObjectMeta.DeletionTimestamp != nil {
		// Log an error
	}

	if pvc.Status.Phase != v1.ClaimBound || pvc.Spec.VolumeName == "" {
		// Log an error
	}

	return pvc, nil
}

func (rm *ResourceManager) getPV(pvc *v1.PersistentVolumeClaim) (*v1.PersistentVolume, error) {
	pv, err := rm.k8sClient.CoreV1().PersistentVolumes().Get(pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv == nil {
		// Log an error
	}

	if pv.Spec.ClaimRef == nil {
		// Log an error
	}

	if pv.Spec.ClaimRef.UID != pvc.UID {
		// Log an error
	}

	return pv, nil
}
