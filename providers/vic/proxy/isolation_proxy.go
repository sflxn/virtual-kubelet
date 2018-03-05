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

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/apiservers/portlayer/client/containers"
	"github.com/vmware/vic/lib/apiservers/portlayer/client/storage"
	"github.com/vmware/vic/lib/apiservers/portlayer/client/tasks"
	//"github.com/vmware/vic/lib/apiservers/engine/backends/convert"

	"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/models"
	"github.com/vmware/vic/pkg/trace"

	"github.com/docker/docker/api/types/strslice"
	"github.com/moby/moby/api/types"

	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/cache"
	"github.com/vmware/vic/pkg/vsphere/sys"
)

type IsolationProxy interface {
	CreateHandle(ctx context.Context) (string, string, error)
	AddImageToHandle(ctx context.Context, handle, deltaID, layerID, imageID, imageName string) (string, error)
	CreateHandleTask(ctx context.Context, handle, id, layerID string, config IsolationContainerConfig) (string, error)
	CommitHandle(ctx context.Context, handle, containerID string, waitTime int32) error
}

type VicIsolationProxy struct {
	client        *client.PortLayer
	imageStore    ImageStore
	podCache      cache.PodCache
	portlayerAddr string
}

type IsolationContainerConfig struct {
	ID        string
	ImageID   string
	LayerID   string
	ImageName string
	Name	  string
	Namespace string

	Cmd        []string
	Path       string
	Entrypoint []string
	Args       []string
	Env        []string
	WorkingDir string
	User       string
	StopSignal string

	Attach    bool
	StdinOnce bool
	OpenStdin bool
	Tty       bool

	CPUCount int64
	Memory int64
}

const (
	// DefaultCPUs - the default number of container VM CPUs
	DefaultCPUs   = 2
	DefaultMemory = 512

	DummyImage    = "f6e427c148a766d2d6c117d67359a0aa7d133b5bc05830a7ff6e8b64ff6b1d1d" //busybox
	DummyLayerID  = "02d3847f0b0fb7acd4419040cc53febf91cb112db2451d9b27a245dee5b227c0" //busybox
	DummyRepoName = "busybox"

	RunningInVCH = false
	HostUUID = "564d3937-7e16-2efd-5b6e-6787a76fe13f"
)

func NewIsolationProxy(plClient *client.PortLayer, portlayerAddr string, imageStore ImageStore, podCache cache.PodCache) IsolationProxy {
	if plClient == nil {
		return nil
	}

	return &VicIsolationProxy{
		client:        plClient,
		imageStore:    imageStore,
		podCache:      podCache,
		portlayerAddr: portlayerAddr,
	}
}

func (v *VicIsolationProxy) CreateHandle(ctx context.Context) (string, string, error) {
	op := trace.FromContext(ctx, "CreateHandle")
	defer trace.End(trace.Begin("", op))

	if v.client == nil {
		return "", "", errors.NillPortlayerClientError("ContainerProxy")
	}

	// Call the Exec port layer to create the container
	var err error
	var host string
	if RunningInVCH {
		host, err = sys.UUID()
	} else {
		host = HostUUID
		err = nil
	}
	if err != nil {
		return "", "", errors.InternalServerError("ContainerProxy.CreateContainerHandle got unexpected error getting VCH UUID")
	}

	plCreateParams := initIsolationConfig(ctx, "", DummyRepoName, DummyImage, DummyLayerID, host)
	createResults, err := v.client.Containers.Create(plCreateParams)
	if err != nil {
		if _, ok := err.(*containers.CreateNotFound); ok {
			cerr := fmt.Errorf("No such image: %s", DummyImage)
			op.Errorf("%s (%s)", cerr, err)
			return "", "", errors.NotFoundError(cerr.Error())
		}

		// If we get here, most likely something went wrong with the port layer API server
		return "", "", errors.InternalServerError(err.Error())
	}

	id := createResults.Payload.ID
	h := createResults.Payload.Handle

	return id, h, nil
}

func (v *VicIsolationProxy) AddImageToHandle(ctx context.Context, handle, deltaID, layerID, imageID, imageName string) (string, error) {
	op := trace.FromContext(ctx, "AddImageToHandle")
	defer trace.End(trace.Begin(handle, op))

	if v.client == nil {
		return "", errors.InternalServerError("ContainerProxy.AddImageToContainer failed to get the portlayer client")
	}

	var err error
	var host string
	if RunningInVCH {
		host, err = sys.UUID()
	} else {
		host = HostUUID
		err = nil
	}
	if err != nil {
		return "", errors.InternalServerError("ContainerProxy.AddImageToContainer got unexpected error getting VCH UUID")
	}

	response, err := v.client.Storage.ImageJoin(storage.NewImageJoinParamsWithContext(ctx).WithStoreName(host).WithID(layerID).
		WithConfig(&models.ImageJoinConfig{
			Handle:   handle,
			DeltaID:  deltaID,
			ImageID:  imageID,
			RepoName: imageName,
		}))
	if err != nil {
		return "", errors.InternalServerError(err.Error())
	}
	handle, ok := response.Payload.Handle.(string)
	if !ok {
		return "", errors.InternalServerError(fmt.Sprintf("Type assertion failed for %#+v", handle))
	}

	return handle, nil
}

func (v *VicIsolationProxy) CreateHandleTask(ctx context.Context, handle, id, layerID string, config IsolationContainerConfig) (string, error) {
	op := trace.FromContext(ctx, "CreateHandleTask")
	defer trace.End(trace.Begin(handle, op))

	if v.client == nil {
		return "", errors.InternalServerError("ContainerProxy.CreateContainerTask failed to create a portlayer client")
	}

	plTaskParams := IsolationContainerConfigToTask(ctx, id, layerID, config)
	plTaskParams.Config.Handle = handle

	responseJoin, err := v.client.Tasks.Join(plTaskParams)
	if err != nil {
		op.Errorf("Unable to join primary task to container: %+v", err)
		return "", errors.InternalServerError(err.Error())
	}

	handle, ok := responseJoin.Payload.Handle.(string)
	if !ok {
		return "", errors.InternalServerError(fmt.Sprintf("Type assertion failed on handle from task join: %#+v", handle))
	}

	plBindParams := tasks.NewBindParamsWithContext(ctx).WithConfig(&models.TaskBindConfig{Handle: handle, ID: id})
	responseBind, err := v.client.Tasks.Bind(plBindParams)
	if err != nil {
		op.Errorf("Unable to bind primary task to container: %+v", err)
		return "", errors.InternalServerError(err.Error())
	}

	handle, ok = responseBind.Payload.Handle.(string)
	if !ok {
		return "", errors.InternalServerError(fmt.Sprintf("Type assertion failed on handle from task bind %#+v", handle))
	}

	return handle, nil
}

func (v *VicIsolationProxy) CommitHandle(ctx context.Context, handle, containerID string, waitTime int32) error {
	op := trace.FromContext(ctx, "CommitHandle")
	defer trace.End(trace.Begin(handle, op))

	if v.client == nil {
		return errors.NillPortlayerClientError("ContainerProxy")
	}

	var commitParams *containers.CommitParams
	if waitTime > 0 {
		commitParams = containers.NewCommitParamsWithContext(ctx).WithHandle(handle).WithWaitTime(&waitTime)
	} else {
		commitParams = containers.NewCommitParamsWithContext(ctx).WithHandle(handle)
	}

	_, err := v.client.Containers.Commit(commitParams)
	if err != nil {
		switch err := err.(type) {
		case *containers.CommitNotFound:
			return errors.NotFoundError(containerID)
		case *containers.CommitConflict:
			return errors.ConflictError(err.Error())
		case *containers.CommitDefault:
			return errors.InternalServerError(err.Payload.Message)
		default:
			return errors.InternalServerError(err.Error())
		}
	}

	return nil
}

//------------------------------------
// Utility Functions
//------------------------------------

// Convert isolation container config to portlayer task param
func IsolationContainerConfigToTask(ctx context.Context, id, layerID string, ic IsolationContainerConfig) *tasks.JoinParams {
	op := trace.NewOperation(context.Background(), "IsolationContainerConfigToTask - %s", id)

	config := &models.TaskJoinConfig{}

	var path string
	var args []string

	// we explicitly specify the ID for the primary task so that it's the same as the containerID
	config.ID = id

	// Set the filesystem namespace this task expects to run in
	config.Namespace = layerID

	// Expand cmd into entrypoint and args
	cmd := strslice.StrSlice(ic.Cmd)
	if len(ic.Entrypoint) != 0 {
		path, args = ic.Entrypoint[0], append(ic.Entrypoint[1:], cmd...)
	} else {
		path, args = cmd[0], cmd[1:]
	}

	// copy the path
	config.Path = path

	// copy the args
	config.Args = make([]string, len(args))
	copy(config.Args, args)

	// copy the env array
	config.Env = make([]string, len(ic.Env))
	copy(config.Env, ic.Env)

	// working dir
	config.WorkingDir = ic.WorkingDir

	// user
	config.User = ic.User

	// attach.  Always set to true otherwise we cannot attach later.
	// this tells portlayer container is attachable.
	config.Attach = true

	// openstdin
	config.OpenStdin = ic.OpenStdin

	// tty
	config.Tty = ic.Tty

	// container stop signal
	config.StopSignal = ic.StopSignal

	op.Debugf("dockerContainerCreateParamsToTask = %+v", config)

	return tasks.NewJoinParamsWithContext(ctx).WithConfig(config)
}

func CreateConfigToString(config types.ContainerCreateConfig) (string, error) {
	buf := bytes.NewBufferString("")
	encoder := json.NewEncoder(buf)
	err := encoder.Encode(config)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// initIsolationConfig returns a default config used to create the isolation unit handle
func initIsolationConfig(ctx context.Context, name, repoName, imageID, layerID, imageStore string) *containers.CreateParams {
	op := trace.NewOperation(context.Background(), "IsolationConfig - %s", name)

	config := &models.ContainerCreateConfig{}

	config.NumCpus = DefaultCPUs
	config.MemoryMB = DefaultMemory

	// Layer/vmdk to use
	config.Layer = layerID

	// Image ID
	config.Image = imageID

	// Repo Requested
	config.RepoName = repoName

	//copy friendly name
	config.Name = name

	// image store
	config.ImageStore = &models.ImageStore{Name: imageStore}

	// network
	config.NetworkDisabled = true

	// hostname
	config.Hostname = "test-kubelet"
	//// domainname - https://github.com/moby/moby/issues/27067
	//config.Domainname = cc.Config.Domainname

	op.Debugf("dockerContainerCreateParamsToPortlayer = %+v", config)

	return containers.NewCreateParamsWithContext(ctx).WithCreateConfig(config)
}