package vic

import (
	"context"
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/vmware/vic/pkg/trace"
)

type VicConfig struct {
	PortlayerAddr	string `yaml:"portlayer-server"`
}

func NewVicConfig(configFile string) VicConfig {
	var config VicConfig

	config.loadConfigFile(configFile)

	return config
}

func (v *VicConfig) loadConfigFile(configFile string) error {
	op := trace.NewOperation(context.Background(), "LoadConfigFile - %s", configFile)
	defer trace.End(trace.Begin("", op))

	contents, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}

	var config VicConfig
	err = yaml.Unmarshal(contents, &config)
	if err != nil {
		err = fmt.Errorf("Unable to unmarshal vic virtual kubelet configfile: %s", err.Error())
		op.Error(err)
		return err
	}

	*v = config

	return nil
}