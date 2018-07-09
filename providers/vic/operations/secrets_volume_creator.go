package operations

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/kr/pretty"

	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/engine/proxy"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/archive"
	"github.com/vmware/vic/lib/constants"
	"github.com/vmware/vic/pkg/trace"

	"github.com/docker/docker/api/types"

	"k8s.io/api/core/v1"
)

type SecretsVolumeCreator interface {
	Create(op trace.Operation, volName string) error
	UpdateSecret(op trace.Operation, name string, data io.Reader, size uint) error
	ProcessSecretsVolumes(op trace.Operation, pod *v1.Pod, rm *manager.ResourceManager) (map[string]string, error)
}

type VicSecretsVolumeCreator struct {
	storageProxy proxy.StorageProxy
	archiveProxy proxy.ArchiveProxy
	volume       *types.Volume
	volName      string
}

// Metadata for the pod vm's tether.  Since this metadata must be built up before the pod vm is instantiated, there are
// no container id yet.  We include container name and container's command for the tether to use to match up with the
// actual realized container instances.
type VicVolumeMount struct {
	v1.VolumeMount
	container_name string `json:"container_name"`
	container_cmds []string `json:"container_cmds"`
}

//-----------------------------------------------------------------------------
// Error types
//-----------------------------------------------------------------------------
type VicSecretsVolumeCreatorError string

func (e VicSecretsVolumeCreatorError) Error() string { return string(e) }

//-----------------------------------------------------------------------------
// Consts
//-----------------------------------------------------------------------------
const (
	DefaultDriverName            = "local"
	TetherSecret                 = "tether.data"
	BaseSecretsFolder            = "/var/run/secrets/kubernetes.io"
	SecretsFolder_ServiceAccount = "/var/run/secrets/kubernetes.io/secretaccount"

	SecretsCreatorInvalidArgs = VicSecretsVolumeCreatorError("VicSecretsVolumeCreator called with invalid args")
)

func NewVicSecretsVolumeCreator(client *client.PortLayer) SecretsVolumeCreator {
	return &VicSecretsVolumeCreator{
		storageProxy: proxy.NewStorageProxy(client),
		archiveProxy: proxy.NewArchiveProxy(client),
	}
}

func (v *VicSecretsVolumeCreator) Create(op trace.Operation, volName string) error {
	defer trace.End(trace.Begin(volName, op))

	if volName == "" {
		return SecretsCreatorInvalidArgs
	}

	exist, err := v.storageProxy.VolumeExist(op, volName)
	if err != nil {
		return err
	}

	if !exist {
		v.volName = volName
		volData := make(map[string]string, 0)
		labels := make(map[string]string, 0)

		// Tell the pod vm about the metadata kv file that will get created when secrets are put on it.
		volData[proxy.OptsKeyValueFileKey] = TetherSecret

		vol, err := v.storageProxy.Create(op, volName, DefaultDriverName, volData, labels)
		if err != nil && !errors.IsVolumeExistError(err) {
			v.volume = nil
			return err
		}

		v.volume = vol
	}

	return nil
}

func (v *VicSecretsVolumeCreator) UpdateSecret(op trace.Operation, name string, data io.Reader, size uint) error {
	defer trace.End(trace.Begin(fmt.Sprintf("vol %s, secret %s", v.volName, name), op))

	filterSpec := archive.GenerateFilterSpec("/", "/", true, archive.CopyTo)
	wg := &sync.WaitGroup{}
	errChan := make(chan error, 1)
	volWriter, err := v.archiveProxy.ArchiveImportWriter(op, constants.VolumeStoreName, v.volName, filterSpec, wg, errChan)
	if err != nil {
		op.Errorf("Unable to get Archive Import Writer for volume %s", v.volName)
		return err
	}

	// Use a tar writer.  By writing out a header to this file, the resulting tar should represent the
	// data as a tar file and cause the portlayer to create a file on the volume with data from the reader.
	secretsTarWriter := tar.NewWriter(volWriter)
	//secretsTarWriter := tar.NewWriter(f)
	secretsTarWriter.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     int64(size),
	})

	if _, err = io.Copy(secretsTarWriter, data); err != nil {
		op.Errorf("Error copying secrets data for %s to volume %s", name, v.volName)
		return err
	}

	secretsTarWriter.Flush()
	secretsTarWriter.Close()

	return nil
}

// ProcessSecretsVolumes creates vmdk volumes with the secrets saved as files on those vmdk volumes.  The volume
//	should later be mounted once the pod vm is started.  If the volume fails to get created, the pod
//	creation should cease to continue further.
//
// arguments:
//		op		operation trace logger
//		pod		pod spec
// returns:
//		map of volume name to destination mount path
func (v *VicSecretsVolumeCreator) ProcessSecretsVolumes(op trace.Operation, pod *v1.Pod, rm *manager.ResourceManager) (map[string]string, error) {
	defer trace.End(trace.Begin(fmt.Sprintf("pod %s", pod.Name), op))

	secretsVols := make(map[string]string, 0)

	for _, vol := range pod.Spec.Volumes {
		if vol.VolumeSource.Secret != nil {
			secret, err := rm.GetSecret(vol.Secret.SecretName, pod.Namespace)
			if err != nil {
				op.Errorf("Found secrets volume %s, but failed to retrieve actual data: %s", err.Error())
				continue
			}

			op.Infof("Found secrets volume %s: %# +v", vol.Name, pretty.Formatter(*secret))

			err = v.Create(op, secret.Name)
			if err != nil {
				op.Errorf("Failed to create a secrets volume %s while creating pod %s", secret.Name, pod.Name)
				return map[string]string{}, err
			}

			for dataName, data := range secret.Data {
				dataReader := bytes.NewReader(data)
				size := len(data)
				err = v.UpdateSecret(op, dataName, dataReader, uint(size))
				if err != nil {
					op.Errorf("Failed to stream secret %s to secret volume %s: %s", dataName, secret.Name, err)
				}
			}

			// Create a meta kv file for the secrets volume so the tether knows how to handle the volumes per container
			// instance
			metaReader, err := v.getContainersMountMeta(op, pod, secret.Name)
			if err != nil {
				//TODO: clean up created secrets volume
				return secretsVols, err
			}
			err = v.UpdateSecret(op, TetherSecret, metaReader, uint(metaReader.Len()))
			if err != nil {
				op.Errorf("Failed to stream secret %s to secret volume %s: %s", TetherSecret, secret.Name, err)
			}

			switch secret.Type {
			case v1.SecretTypeServiceAccountToken:
				secretsVols[secret.Name] = SecretsFolder_ServiceAccount
			default:
				//TODO:  Need to figure out dest path of all the secrets types
				secretsVols[secret.Name] = "/" + secret.Name
			}
		}
	}

	return secretsVols, nil
}

func (v *VicSecretsVolumeCreator) getContainersMountMeta(op trace.Operation, pod *v1.Pod, secretName string) (*bytes.Reader, error) {
	defer trace.End(trace.Begin(fmt.Sprintf("pod %s, secret %s", pod.Name, secretName), op))

	meta := make([]VicVolumeMount, 0)

	for _, c := range pod.Spec.Containers {
		for _, mnt := range c.VolumeMounts {
			if mnt.Name == secretName {
				mountData := VicVolumeMount{
					VolumeMount:    mnt,
					container_name: c.Name,
					container_cmds: c.Command,
				}

				meta = append(meta, mountData)
			}
		}
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		op.Error("Failed to marshal secrets %s's metadata: %s", secretName, err.Error())
		return nil, err
	}

	return bytes.NewReader(metaBytes), nil
}
