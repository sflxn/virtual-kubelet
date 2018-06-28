package operations

import (
	"archive/tar"
	"fmt"
	"io"
	//"os"
	"sync"

	"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/engine/proxy"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/archive"
	"github.com/vmware/vic/lib/constants"
	"github.com/vmware/vic/pkg/trace"

	"github.com/docker/docker/api/types"
)

type SecretsVolumeCreator interface {
	Create(op trace.Operation, volName string) error
	UpdateSecret(op trace.Operation, name string, data io.Reader, size uint) error
}

type VicSecretsVolumeCreator struct {
	storageProxy proxy.StorageProxy
	archiveProxy proxy.ArchiveProxy
	volume       *types.Volume
	volName      string
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
	DefaultDriveName          = "local"
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
		vol, err := v.storageProxy.Create(op, volName, DefaultDriveName, volData, labels)
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
