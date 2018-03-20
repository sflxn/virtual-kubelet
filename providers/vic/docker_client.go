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

package vic

import (
	"fmt"
	"net/http"

	"github.com/vmware/vic/pkg/trace"
)

// Super simplistic docker client for the virtual kubelet to perform some operations
type DockerClient interface {
	Ping(op trace.Operation) error
}

type VicDockerClient struct {
	serverAddr string
}

func NewVicDockerClient(personaAddr string) DockerClient {
	return &VicDockerClient{
		serverAddr: personaAddr,
	}
}

func (v *VicDockerClient) Ping(op trace.Operation) error {
	personaServer := fmt.Sprintf("http://%s/v1.35/info", v.serverAddr)
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
