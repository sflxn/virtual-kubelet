package vic

import (
	"context"

	"github.com/vmware/vic/lib/apiservers/engine/backends/cache"
	//"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	"github.com/vmware/vic/lib/metadata"
)

type VicImageStore interface {
	Get(idOrRef string) (metadata.ImageConfig, error)
	GetImages() []*metadata.ImageConfig
}

type ImageStore struct {
	client        *client.PortLayer
}

func NewImageStore(plClient *client.PortLayer) (VicImageStore, error) {
	err := cache.InitializeImageCache(plClient)
	if err != nil {
		return nil, err
	}

	//return cache.ImageCache(), error

	//return cache.ImageCache()
	vs := &ImageStore{client: plClient}

	return vs, nil
}

func (i *ImageStore) Rehydrate(ctx *context.Context) error {
	err := cache.InitializeImageCache(i.client)
	if err != nil {
		return err
	}

	return nil
}

func (i *ImageStore) Get(idOrRef string) (*metadata.ImageConfig, error) {
	return cache.ImageCache().Get(idOrRef)
}

