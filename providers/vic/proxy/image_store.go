package proxy

import (
	"context"

	"github.com/vmware/vic/lib/apiservers/engine/backends/cache"
	//"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/metadata"
)

type ImageStore interface {
	Get(ctx context.Context, idOrRef string) (*metadata.ImageConfig, error)
	GetImages(ctx context.Context) []*metadata.ImageConfig
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

func (v *VicImageStore) Get(ctx context.Context, idOrRef string) (*metadata.ImageConfig, error) {
	return cache.ImageCache().Get(idOrRef)
}

func (v *VicImageStore) GetImages(ctx context.Context) []*metadata.ImageConfig {
	return nil
}
