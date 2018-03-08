package vic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/cache"
	"github.com/virtual-kubelet/virtual-kubelet/providers/vic/proxy"
	"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/pkg/trace"
	"github.com/vmware/vic/lib/metadata"

	"k8s.io/api/core/v1"
)

type PodCreator interface {
}

type VicPodCreator struct {
	client        *client.PortLayer
	imageStore    proxy.ImageStore
	podCache      cache.PodCache
	personaAddr   string
	portlayerAddr string
}

type CreateResponse struct {
	Id       string `json:"Id"`
	Warnings string `json:"Warnings"`
}

const (
	// MemoryAlignMB is the value to which container VM memory must align in order for hotadd to work
	MemoryAlignMB = 128
	// MemoryMinMB - the minimum allowable container memory size
	MemoryMinMB = 512
	// MemoryDefaultMB - the default container VM memory size
	MemoryDefaultMB = 2048
	// MinCPUs - the minimum number of allowable CPUs the container can use
	MinCPUs = 1
	// DefaultCPUs - the default number of container VM CPUs
	DefaultCPUs   = 2
	DefaultMemory = 512
	MiBytesUnit   = 1024 * 1024

	UsePortlayerProvisioner = true

	defaultEnvPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

func NewPodCreator(client *client.PortLayer, imageStore proxy.ImageStore, podCache cache.PodCache, personaAddr string, portlayerAddr string) *VicPodCreator {
	return &VicPodCreator{
		client:        client,
		imageStore:    imageStore,
		podCache:      podCache,
		personaAddr:   personaAddr,
		portlayerAddr: portlayerAddr,
	}
}

func (v *VicPodCreator) CreatePod(ctx context.Context, name string, pod *v1.Pod) error {
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
	if UsePortlayerProvisioner {
		// Transform kube container config to docker create config
		err := v.portlayerCreatePod(ctx, &pod.Spec)
		if err != nil {
			return err
		}

		err = v.podCache.Add(ctx, name, pod)
		if err != nil {
			//TODO:  What should we do if pod already exist?
		}

	} else {
		for _, c := range pod.Spec.Containers {
			createString := DummyCreateSpec(c.Image, c.Command)

			err = v.personaCreateContainer(ctx, createString)
			if err != nil && c.ImagePullPolicy == v1.PullIfNotPresent {
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

	return nil
}

func (v *VicPodCreator) pingPersona(ctx context.Context) error {
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

func (v *VicPodCreator) personaCreateContainer(ctx context.Context, config string) error {
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
	op.Infof("Response from docker create: body = %s", string(body))
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

func (v *VicPodCreator) personaPullContainer(ctx context.Context, image string) error {
	op := trace.FromContext(ctx, "CreatePod")

	pullClient := &http.Client{Timeout: 60 * time.Second}
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

func (v *VicPodCreator) portlayerCreatePod(ctx context.Context, spec *v1.PodSpec) error {
	op := trace.FromContext(ctx, "portlayerCreateContainer")
	defer trace.End(trace.Begin("", op))

	ip := proxy.NewIsolationProxy(v.client, v.portlayerAddr, v.imageStore, v.podCache)

	id, h, err := ip.CreateHandle(ctx)
	if err != nil {
		return err
	}

	for idx, c := range spec.Containers {
		// Pull image config from VIC's image store if policy allows
		var realize bool
		if c.ImagePullPolicy == v1.PullIfNotPresent {
			realize = true
		} else {
			realize = false
		}

		imgConfig, err := v.imageStore.Get(op.Context, c.Image, "", realize)
		if err != nil {
			err = fmt.Errorf("VicPodCreator failed to get image %s's config from the image store: %s", err.Error())
			op.Error(err)
			return err
		}

		op.Info("** Receive image config from imagestore = %#v", imgConfig)

		// Create the initial config
		ic, err := IsolationContainerConfigFromKubeContainer(ctx, &c, imgConfig)
		if err != nil {
			return err
		}

		h, err = ip.AddImageToHandle(ctx, h, c.Name, imgConfig.V1Image.ID, imgConfig.ImageID, imgConfig.Name)
		if err != nil {
			return err
		}

		//TODO: Fix this!
		//HACK: only create task for 1st container.  portlayer does not yet handle adding tasks for every containers.
		if idx == 0 {
			h, err = ip.CreateHandleTask(ctx, h, id, imgConfig.V1Image.ID, ic)
			if err != nil {
				return err
			}
		}
	}

	//// HACK: injects an alpine image
	//h, err = ip.AddImageToHandle(ctx, h, "hacked-in-alpine", "9797e5e798a034d53525968de25bd25c913e7bb17c6d068ebc778cb33e3ff6e5", "3fd9065eaf02feaf94d68376da52541925650b81698c53c6824d92ff63f98353", config)
	//if err != nil {
	//	return err
	//}

	err = ip.CommitHandle(ctx, h, id, -1)
	if err != nil {
		return err
	}

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
			` + command + `
			],
			"Image":"` + image + `",
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

func IsolationContainerConfigFromKubeContainer(ctx context.Context, cSpec *v1.Container, imgConfig *metadata.ImageConfig) (proxy.IsolationContainerConfig, error) {
	op := trace.FromContext(ctx, "portlayerCreateContainer")
	defer trace.End(trace.Begin("", op))

	config := proxy.IsolationContainerConfig{
		Name:       cSpec.Name,
		WorkingDir: cSpec.WorkingDir,
		ImageName:  cSpec.Image,
		Tty:        cSpec.TTY,
		StdinOnce:  cSpec.StdinOnce,
		OpenStdin:  cSpec.Stdin,
	}

	setResourceFromKubeSpec(ctx, &config, cSpec)

	// Overwrite or append the image's config from the CLI with the metadata from the image's
	// layer metadata where appropriate
	if len(cSpec.Command) > 0 {
		config.Cmd = make([]string, len(cSpec.Command))
		copy(config.Cmd, cSpec.Command)

		config.Cmd = append(config.Cmd, cSpec.Args...)
	} else {
		config.Cmd = make([]string, len(imgConfig.Config.Cmd))
		copy(config.Cmd, imgConfig.Config.Cmd)
	}

	config.User = ""
	if imgConfig.Config.User != "" {
		config.User = imgConfig.Config.User
	}

	// set up environment
	config.Env = setEnvFromImageConfig(config.Tty, config.Env, imgConfig.Config.Env)

	op.Infof("config = %#v", config)

	// TODO:  Cache the container (so that they are shared with the persona)

	return config, nil
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

func setResourceFromKubeSpec(ctx context.Context, config *proxy.IsolationContainerConfig, cSpec *v1.Container) error {
	op := trace.FromContext(ctx, "")

	if config == nil {
		return errors.BadRequestError("invalid config")
	}

	// Get resource request.  If not specified, use the limits.  If that's not set, use default VIC values.
	config.CPUCount = cSpec.Resources.Requests.Cpu().Value()
	if config.CPUCount == 0 {
		config.CPUCount = cSpec.Resources.Limits.Cpu().Value()
		if config.CPUCount == 0 {
			config.CPUCount = DefaultCPUs
		}
	}
	config.Memory = cSpec.Resources.Requests.Memory().Value()
	if config.Memory == 0 {
		config.Memory = cSpec.Resources.Limits.Memory().Value()
		if config.Memory == 0 {
			config.Memory = DefaultMemory
		}
	}

	// convert from bytes to MiB for vsphere
	memoryMB := config.Memory / MiBytesUnit
	if memoryMB == 0 {
		memoryMB = MemoryDefaultMB
	} else if memoryMB < MemoryMinMB {
		memoryMB = MemoryMinMB
	}

	// check that memory is aligned
	if remainder := memoryMB % MemoryAlignMB; remainder != 0 {
		op.Warnf("Default container VM memory must be %d aligned for hotadd, rounding up.", MemoryAlignMB)
		memoryMB += MemoryAlignMB - remainder
	}

	config.Memory = memoryMB
	op.Infof("Container memory: %d MB", config.Memory)

	return nil
}

//// validateCreateConfig() checks the parameters for ContainerCreate().
//// It may "fix up" the config param passed into ConntainerCreate() if needed.
//func validateIsolationConfig(config *proxy.IsolationContainerConfig, cSpec v1.Container) error {
//	defer trace.End(trace.Begin("Container.validateCreateConfig"))
//
//	if config == nil {
//		return errors.BadRequestError("invalid config")
//	}
//
//	// process cpucount here
//	var cpuCount int64 = proxy.DefaultCPUs
//
//	// support windows client
//	if config.CPUCount > 0 {
//		cpuCount = config.CPUCount
//	} else {
//		// we hijack --cpuset-cpus in the non-windows case
//		if config.HostConfig.CpusetCpus != "" {
//			cpus := strings.Split(config.HostConfig.CpusetCpus, ",")
//			if c, err := strconv.Atoi(cpus[0]); err == nil {
//				cpuCount = int64(c)
//			} else {
//				return fmt.Errorf("Error parsing CPU count: %s", err)
//			}
//		}
//	}
//	config.CPUCount = cpuCount
//
//	// fix-up cpu/memory settings here
//	if cpuCount < MinCPUs {
//		config.HostConfig.CPUCount = MinCPUs
//	}
//	log.Infof("Container CPU count: %d", config.HostConfig.CPUCount)
//
//	// convert from bytes to MiB for vsphere
//	memoryMB := config.HostConfig.Memory / units.MiB
//	if memoryMB == 0 {
//		memoryMB = MemoryDefaultMB
//	} else if memoryMB < MemoryMinMB {
//		memoryMB = MemoryMinMB
//	}
//
//	// check that memory is aligned
//	if remainder := memoryMB % MemoryAlignMB; remainder != 0 {
//		log.Warnf("Default container VM memory must be %d aligned for hotadd, rounding up.", MemoryAlignMB)
//		memoryMB += MemoryAlignMB - remainder
//	}
//
//	config.HostConfig.Memory = memoryMB
//	log.Infof("Container memory: %d MB", config.HostConfig.Memory)
//
//	//if config.NetworkingConfig == nil {
//	//	config.NetworkingConfig = &dnetwork.NetworkingConfig{}
//	//} else {
//	//	if l := len(config.NetworkingConfig.EndpointsConfig); l > 1 {
//	//		return fmt.Errorf("NetworkMode error: Container can be connected to one network endpoint only")
//	//	}
//	//	// If NetworkConfig exists, set NetworkMode to the default endpoint network, assuming only one endpoint network as the default network during container create
//	//	for networkName := range config.NetworkingConfig.EndpointsConfig {
//	//		config.HostConfig.NetworkMode = containertypes.NetworkMode(networkName)
//	//	}
//	//}
//
//	// validate port bindings
//	var ips []string
//	if addrs, err := network.PublicIPv4Addrs(); err != nil {
//		log.Warnf("could not get address for public interface: %s", err)
//	} else {
//		ips = make([]string, len(addrs))
//		for i := range addrs {
//			ips[i] = addrs[i]
//		}
//	}
//
//	for _, pbs := range config.HostConfig.PortBindings {
//		for _, pb := range pbs {
//			if pb.HostIP != "" && pb.HostIP != "0.0.0.0" {
//				// check if specified host ip equals any of the addresses on the "client" interface
//				found := false
//				for _, i := range ips {
//					if i == pb.HostIP {
//						found = true
//						break
//					}
//				}
//				if !found {
//					return engerr.InternalServerError("host IP for port bindings is only supported for 0.0.0.0 and the public interface IP address")
//				}
//			}
//
//			// #nosec: Errors unhandled.
//			start, end, _ := nat.ParsePortRangeToInt(pb.HostPort)
//			if start != end {
//				return engerr.InternalServerError("host port ranges are not supported for port bindings")
//			}
//		}
//	}
//
//	// https://github.com/vmware/vic/issues/1378
//	if len(config.Config.Entrypoint) == 0 && len(config.Config.Cmd) == 0 {
//		return derr.NewRequestNotFoundError(fmt.Errorf("No command specified"))
//	}
//
//	return nil
//}
