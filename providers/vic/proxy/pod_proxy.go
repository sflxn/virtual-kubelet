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
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	units "github.com/docker/go-units"
	engerr "github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/pkg/trace"

	"github.com/docker/docker/api/types/container"
	"github.com/moby/moby/api/types"
	"k8s.io/api/core/v1"

	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/cache"
)

type PodProxy interface {
	CreatePod(ctx context.Context, name string, pod *v1.Pod) error
}

type VicPodProxy struct {
	client        *client.PortLayer
	imageStore    ImageStore
	podCache      cache.PodCache
	personaAddr   string
	portlayerAddr string
}

type CreateResponse struct {
	Id       string `json:"Id"`
	Warnings string `json:"Warnings"`
}

const (
	defaultEnvPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	// MemoryAlignMB is the value to which container VM memory must align in order for hotadd to work
	MemoryAlignMB = 128
	// MemoryMinMB - the minimum allowable container memory size
	MemoryMinMB = 512
	// MemoryDefaultMB - the default container VM memory size
	MemoryDefaultMB = 2048
	// MinCPUs - the minimum number of allowable CPUs the container can use
	MinCPUs = 1
	// DefaultCPUs - the default number of container VM CPUs
	DefaultCPUs = 2

	UsePortlayerProvisioner = false
)

func NewPodProxy(plClient *client.PortLayer, personaAddr, portlayerAddr string, imageStore ImageStore, podCache cache.PodCache) PodProxy {
	if plClient == nil {
		return nil
	}

	return &VicPodProxy{
		client:        plClient,
		imageStore:    imageStore,
		podCache:      podCache,
		personaAddr:   personaAddr,
		portlayerAddr: portlayerAddr,
	}
}

func (v *VicPodProxy) CreatePod(ctx context.Context, name string, pod *v1.Pod) error {
	op := trace.FromContext(ctx, "CreatePod")
	defer trace.End(trace.Begin(pod.Name, op))

	var err error

	for i := 0; i < 30; i++ {
		err = v.pingPersona(ctx)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Create each container.  Only for prototype only.
	for _, c := range pod.Spec.Containers {
		// Transform kube container config to docker create config
		createConfig := KubeSpecToDockerCreateSpec(c)
		if UsePortlayerProvisioner {
			err := v.portlayerCreateContainer(ctx, createConfig)
			if err != nil {
				op.Errorf("Failed to create container %s for pod %s", createConfig.Name, pod.Name)
			}
		} else {
			createString := DummyCreateSpec(c.Image, c.Command)

			err = v.personaCreateContainer(ctx, createString)
			if err != nil {
				err = v.personaPullContainer(ctx, c.Image)
				if err != nil {
					return err
				}

					err = v.personaCreateContainer(ctx, createString)
				if err != nil {
					return err
				}
			}
		}
	}

	err = v.podCache.Add(ctx, name, pod)
	if err != nil {
		//TODO:  What should we do if pod already exist?
	}

	return nil
}

func (v *VicPodProxy) pingPersona(ctx context.Context) error {
	op := trace.FromContext(ctx, "CreatePod")

	personaServer := fmt.Sprintf("http://%s/v1.35/info", v.personaAddr)
	resp, err := http.Get(personaServer)
	if err != nil {
		op.Errorf("Ping failed: error = %s", err.Error())
		return err
	}

	if resp.StatusCode >= 300 {
		op.Errorf("Ping failed: status = %d", resp.StatusCode)
		return fmt.Errorf("Server Error")
	}

	return nil
}

func (v *VicPodProxy) personaCreateContainer(ctx context.Context, config string) error {
	op := trace.FromContext(ctx, "CreatePod")

	personaServer := fmt.Sprintf("http://%s/v1.35/containers/create", v.personaAddr)
	reader := bytes.NewBuffer([]byte(config))
	resp, err := http.Post(personaServer, "application/json", reader)
	if err != nil {
		op.Errorf("Error from from docker create: error = %s", err.Error())
		return err
	}
	if resp.StatusCode >= 300 {
		op.Errorf("Error from from docker create: status = %d", resp.StatusCode)
		return fmt.Errorf("Image not found")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	op.Infof("Response from docker create: status = %d", resp.StatusCode)
	op.Infof("Response from docker create: bod = %s", string(body))
	var createResp CreateResponse
	err = json.Unmarshal(body, &createResp)
	if err != nil {
		op.Errorf("Failed to unmarshal response from container create post")
		return err
	}
	startContainerUrl := fmt.Sprintf("http://%s/v1.35/containers/%s/start", v.personaAddr, createResp.Id)
	op.Infof("Starting container with request - %s", startContainerUrl)
	_, err = http.Post(startContainerUrl, "", nil)
	if err != nil {
		op.Errorf("Failed to start container %s", createResp.Id)
		return err
	}

	return nil
}

func (v *VicPodProxy) personaPullContainer(ctx context.Context, image string) error {
	op := trace.FromContext(ctx, "CreatePod")

	pullClient := &http.Client{Timeout:60 * time.Second}
	personaServer := fmt.Sprintf("http://%s/v1.35/images/create?fromImage=%s", v.personaAddr, image)
	op.Infof("POST %s", personaServer)
	reader := bytes.NewBuffer([]byte(""))
	resp, err := pullClient.Post(personaServer, "application/json", reader)
	if err != nil {
		op.Errorf("Error from docker pull: error = %s", err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("Error from docker pull: status = %d", resp.StatusCode)
		op.Errorf(msg)
		return fmt.Errorf(msg)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("Error reading docker pull response: error = %s", err.Error())
		op.Errorf(msg)
		return fmt.Errorf(msg)
	}
	op.Infof("Response from docker pull: body = %s", string(body))

	return nil
}

func (v *VicPodProxy) portlayerCreateContainer(ctx context.Context, config types.ContainerCreateConfig) error {
	op := trace.FromContext(ctx, "createContainer")
	defer trace.End(trace.Begin("", op))

	//// Pull image config from VIC's image store
	//image, err := v.imageStore.Get(op.Context, config.Config.Image, "", true)
	//if err != nil {
	//	err = fmt.Errorf("PodProxy failed to get image %s's config from the image store: %s", err.Error())
	//	op.Error(err)
	//	return err
	//}
	//
	//setCreateConfigOptions(config.Config, image.Config)
	//op.Infof("config = %#v", config.Config)

	return nil
}

//------------------------------------
// Utility Functions
//------------------------------------

func DummyCreateSpec(image string, cmd []string) string {
	var command string
	for i, c := range cmd {
		if i == 0 {
			command = fmt.Sprintf("\"%s\"", c)
		} else {
			command = command + fmt.Sprintf(", \"%s\"", c)
		}
	}

	config := `{
			"Hostname":"",
			"Domainname":"",
			"User":"",
			"AttachStdin":false,
			"AttachStdout":false,
			"AttachStderr":false,
			"Tty":false,
			"OpenStdin":false,
			"StdinOnce":false,
			"Env":[

			],
			"Cmd":[
			`+command+`
			],
			"Image":"`+image+`",
			"Volumes":{

		},
		"WorkingDir":"",
		"Entrypoint":null,
		"OnBuild":null,
		"Labels":{

		},
		"HostConfig":{
		"Binds":null,
		"ContainerIDFile":"",
		"LogConfig":{
		"Type":"",
		"Config":{

		}
		},
		"NetworkMode":"default",
		"PortBindings":{

		},
		"RestartPolicy":{
		"Name":"no",
		"MaximumRetryCount":0
		},
		"AutoRemove":false,
		"VolumeDriver":"",
		"VolumesFrom":null,
		"CapAdd":null,
		"CapDrop":null,
		"Dns":[

		],
		"DnsOptions":[

		],
		"DnsSearch":[

		],
		"ExtraHosts":null,
		"GroupAdd":null,
		"IpcMode":"",
		"Cgroup":"",
		"Links":null,
		"OomScoreAdj":0,
		"PidMode":"",
		"Privileged":false,
		"PublishAllPorts":false,
		"ReadonlyRootfs":false,
		"SecurityOpt":null,
		"UTSMode":"",
		"UsernsMode":"",
		"ShmSize":0,
		"ConsoleSize":[
		0,
		0
		],
		"Isolation":"",
		"CpuShares":0,
		"Memory":0,
		"NanoCpus":0,
		"CgroupParent":"",
		"BlkioWeight":0,
		"BlkioWeightDevice":[

		],
		"BlkioDeviceReadBps":null,
		"BlkioDeviceWriteBps":null,
		"BlkioDeviceReadIOps":null,
		"BlkioDeviceWriteIOps":null,
		"CpuPeriod":0,
		"CpuQuota":0,
		"CpuRealtimePeriod":0,
		"CpuRealtimeRuntime":0,
		"CpusetCpus":"",
		"CpusetMems":"",
		"Devices":[

		],
		"DeviceCgroupRules":null,
		"DiskQuota":0,
		"KernelMemory":0,
		"MemoryReservation":0,
		"MemorySwap":0,
		"MemorySwappiness":-1,
		"OomKillDisable":false,
		"PidsLimit":0,
		"Ulimits":null,
		"CpuCount":0,
		"CpuPercent":0,
		"IOMaximumIOps":0,
		"IOMaximumBandwidth":0
		},
		"NetworkingConfig":{
		"EndpointsConfig":{

		}
		}
		}`

	return config
}

// TODO: refactor so we no longer need to know about docker types
func KubeSpecToDockerCreateSpec(cSpec v1.Container) types.ContainerCreateConfig {
	config := types.ContainerCreateConfig{
		Name: cSpec.Name,
		Config: &container.Config{
			WorkingDir: cSpec.WorkingDir,
			Image:      cSpec.Image,
			Tty:        cSpec.TTY,
			StdinOnce:  cSpec.StdinOnce,
			OpenStdin:  cSpec.Stdin,
		},
		HostConfig: &container.HostConfig{
		//container.Resources.CPUCount:
		},
	}

	if len(cSpec.Command) != 0 {
		config.Config.Cmd = cSpec.Command
	}

	//TODO:  Handle kube container's args (cSpec.Args)

	config.HostConfig.Resources.CPUCount = cSpec.Resources.Limits.Cpu().Value()
	config.HostConfig.Resources.Memory = cSpec.Resources.Limits.Memory().Value()

	return config
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

// SetConfigOptions is a place to add necessary container configuration
// values that were not explicitly supplied by the user
func setCreateConfigOptions(config, imageConfig *container.Config) {
	// Overwrite or append the image's config from the CLI with the metadata from the image's
	// layer metadata where appropriate
	if len(config.Cmd) == 0 {
		config.Cmd = imageConfig.Cmd
	}
	if config.WorkingDir == "" {
		config.WorkingDir = imageConfig.WorkingDir
	}
	if len(config.Entrypoint) == 0 {
		config.Entrypoint = imageConfig.Entrypoint
	}

	if config.Volumes == nil {
		config.Volumes = imageConfig.Volumes
	} else {
		for k, v := range imageConfig.Volumes {
			//NOTE: the value of the map is an empty struct.
			//      we also do not care about duplicates.
			//      This Volumes map is really a Set.
			config.Volumes[k] = v
		}
	}

	if config.User == "" {
		config.User = imageConfig.User
	}
	// set up environment
	config.Env = setEnvFromImageConfig(config.Tty, config.Env, imageConfig.Env)
}

func setEnvFromImageConfig(tty bool, env []string, imgEnv []string) []string {
	// Set PATH in ENV if needed
	env = setPathFromImageConfig(env, imgEnv)

	containerEnv := make(map[string]string, len(env))
	for _, e := range env {
		kv := strings.SplitN(e, "=", 2)
		var val string
		if len(kv) == 2 {
			val = kv[1]
		}
		containerEnv[kv[0]] = val
	}

	// Set TERM to xterm if tty is set, unless user supplied a different TERM
	if tty {
		if _, ok := containerEnv["TERM"]; !ok {
			env = append(env, "TERM=xterm")
		}
	}

	// add remaining environment variables from the image config to the container
	// config, taking care not to overwrite anything
	for _, imageEnv := range imgEnv {
		key := strings.SplitN(imageEnv, "=", 2)[0]
		// is environment variable already set in container config?
		if _, ok := containerEnv[key]; !ok {
			// no? let's copy it from the image config
			env = append(env, imageEnv)
		}
	}

	return env
}

func setPathFromImageConfig(env []string, imgEnv []string) []string {
	// check if user supplied PATH environment variable at creation time
	for _, v := range env {
		if strings.HasPrefix(v, "PATH=") {
			// a PATH is set, bail
			return env
		}
	}

	// check to see if the image this container is created from supplies a PATH
	for _, v := range imgEnv {
		if strings.HasPrefix(v, "PATH=") {
			// a PATH was found, add it to the config
			env = append(env, v)
			return env
		}
	}

	// no PATH set, use the default
	env = append(env, fmt.Sprintf("PATH=%s", defaultEnvPath))

	return env
}

// validateCreateConfig() checks the parameters for ContainerCreate().
// It may "fix up" the config param passed into ConntainerCreate() if needed.
func validateCreateConfig(config *types.ContainerCreateConfig) error {
	defer trace.End(trace.Begin("Container.validateCreateConfig"))

	if config.Config == nil {
		return engerr.BadRequestError("invalid config")
	}

	if config.HostConfig == nil {
		config.HostConfig = &container.HostConfig{}
	}

	// process cpucount here
	var cpuCount int64 = DefaultCPUs

	// support windows client
	if config.HostConfig.CPUCount > 0 {
		cpuCount = config.HostConfig.CPUCount
	} else {
		// we hijack --cpuset-cpus in the non-windows case
		if config.HostConfig.CpusetCpus != "" {
			cpus := strings.Split(config.HostConfig.CpusetCpus, ",")
			if c, err := strconv.Atoi(cpus[0]); err == nil {
				cpuCount = int64(c)
			} else {
				return fmt.Errorf("Error parsing CPU count: %s", err)
			}
		}
	}
	config.HostConfig.CPUCount = cpuCount

	// fix-up cpu/memory settings here
	if cpuCount < MinCPUs {
		config.HostConfig.CPUCount = MinCPUs
	}
	log.Infof("Container CPU count: %d", config.HostConfig.CPUCount)

	// convert from bytes to MiB for vsphere
	memoryMB := config.HostConfig.Memory / units.MiB
	if memoryMB == 0 {
		memoryMB = MemoryDefaultMB
	} else if memoryMB < MemoryMinMB {
		memoryMB = MemoryMinMB
	}

	// check that memory is aligned
	if remainder := memoryMB % MemoryAlignMB; remainder != 0 {
		log.Warnf("Default container VM memory must be %d aligned for hotadd, rounding up.", MemoryAlignMB)
		memoryMB += MemoryAlignMB - remainder
	}

	config.HostConfig.Memory = memoryMB
	log.Infof("Container memory: %d MB", config.HostConfig.Memory)

	////if config.NetworkingConfig == nil {
	////	config.NetworkingConfig = &dnetwork.NetworkingConfig{}
	////} else {
	////	if l := len(config.NetworkingConfig.EndpointsConfig); l > 1 {
	////		return fmt.Errorf("NetworkMode error: Container can be connected to one network endpoint only")
	////	}
	////	// If NetworkConfig exists, set NetworkMode to the default endpoint network, assuming only one endpoint network as the default network during container create
	////	for networkName := range config.NetworkingConfig.EndpointsConfig {
	////		config.HostConfig.NetworkMode = containertypes.NetworkMode(networkName)
	////	}
	////}
	//
	//// validate port bindings
	//var ips []string
	//if addrs, err := network.PublicIPv4Addrs(); err != nil {
	//	log.Warnf("could not get address for public interface: %s", err)
	//} else {
	//	ips = make([]string, len(addrs))
	//	for i := range addrs {
	//		ips[i] = addrs[i]
	//	}
	//}
	//
	//for _, pbs := range config.HostConfig.PortBindings {
	//	for _, pb := range pbs {
	//		if pb.HostIP != "" && pb.HostIP != "0.0.0.0" {
	//			// check if specified host ip equals any of the addresses on the "client" interface
	//			found := false
	//			for _, i := range ips {
	//				if i == pb.HostIP {
	//					found = true
	//					break
	//				}
	//			}
	//			if !found {
	//				return engerr.InternalServerError("host IP for port bindings is only supported for 0.0.0.0 and the public interface IP address")
	//			}
	//		}
	//
	//		// #nosec: Errors unhandled.
	//		start, end, _ := nat.ParsePortRangeToInt(pb.HostPort)
	//		if start != end {
	//			return engerr.InternalServerError("host port ranges are not supported for port bindings")
	//		}
	//	}
	//}
	//
	//// https://github.com/vmware/vic/issues/1378
	//if len(config.Config.Entrypoint) == 0 && len(config.Config.Cmd) == 0 {
	//	return derr.NewRequestNotFoundError(fmt.Errorf("No command specified"))
	//}

	return nil
}
