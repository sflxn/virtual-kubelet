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
	"context"

	"github.com/vmware/vic/lib/apiservers/engine/backends/cache"
	//"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/metadata"
)

type ImageStore interface {
	Get(ctx context.Context, idOrRef string, actuate bool) (*metadata.ImageConfig, error)
	GetImages(ctx context.Context) []*metadata.ImageConfig
	PullImage(ctx context.Context, name string) error
}

type VicImageStore struct {
	client        *client.PortLayer
}

func NewImageStore(plClient *client.PortLayer) (ImageStore, error) {
	err := cache.InitializeImageCache(plClient)
	if err != nil {
		return nil, err
	}

	vs := &VicImageStore{client: plClient}

	return vs, nil
}

// Get returns an ImageConfig.  If the config is not cached, VicImageStore can request
// imagec to pull the image if actuate is set to true.
func (v *VicImageStore) Get(ctx context.Context, idOrRef string, actuate bool) (*metadata.ImageConfig, error) {
	c, err := cache.ImageCache().Get(idOrRef)
	if err != nil && actuate {
		err = v.PullImage(ctx, idOrRef)
	}

	if err != nil {
		return nil, err
	}

	return c, nil
}

func (v *VicImageStore) GetImages(ctx context.Context) []*metadata.ImageConfig {
	return nil
}

func (v *VicImageStore) PullImage(ctx context.Context, name string) error {
	return nil
}
