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
	//"net/url"
	//"os"
	//"strings"

	//"github.com/vmware/vic/lib/apiservers/engine/backends/cache"
	//"github.com/vmware/vic/lib/apiservers/engine/errors"
	"github.com/vmware/vic/lib/apiservers/portlayer/client"
	//"github.com/vmware/vic/lib/imagec"
	"github.com/vmware/vic/lib/metadata"
	//"github.com/vmware/vic/pkg/trace"
	//"github.com/docker/docker/reference"

	//"github.com/docker/distribution/digest"
	//"github.com/docker/distribution/reference"
)

type ImageStore interface {
	Get(ctx context.Context, idOrRef, tag string, actuate bool) (*metadata.ImageConfig, error)
	GetImages(ctx context.Context) []*metadata.ImageConfig
	PullImage(ctx context.Context, image, tag, username, password string) error
}

type VicImageStore struct {
	client        *client.PortLayer
	portlayerAddr string
}

func NewImageStore(plClient *client.PortLayer, portlayerAddr string) (ImageStore, error) {
	//err := cache.InitializeImageCache(plClient)
	//if err != nil {
	//	return nil, err
	//}

	vs := &VicImageStore{
		client:        plClient,
		portlayerAddr: portlayerAddr,
	}

	return vs, nil
}

// Get returns an ImageConfig.  If the config is not cached, VicImageStore can request
// imagec to pull the image if actuate is set to true.
func (v *VicImageStore) Get(ctx context.Context, idOrRef, tag string, actuate bool) (*metadata.ImageConfig, error) {
	//op := trace.FromContext(ctx, "Get - %s:%s", idOrRef, tag)
	//defer trace.End(trace.Begin("", op))
	//
	//c, err := cache.ImageCache().Get(idOrRef)
	//if err != nil && actuate {
	//	err = v.PullImage(ctx, idOrRef, tag, "", "")
	//}
	//
	//if err != nil {
	//	return nil, err
	//}
	//
	//return c, nil
	return nil, nil
}

func (v *VicImageStore) GetImages(ctx context.Context) []*metadata.ImageConfig {
	return nil
}

// PullImage makes sure our shared imagestore (with VIC's docker) has the image
// TODO: We need to rewrite this function so there is no need to pull in docker imports.
// TODO: We need to refactor out the whitelist handling in VIC's docker persona to work with the virtual-kubelet
func (v *VicImageStore) PullImage(ctx context.Context, image, tag, username, password string) error {
	//op := trace.FromContext(ctx, "Get - %s:%s", image, tag)
	//defer trace.End(trace.Begin("", op))
	//
	////***** Code from Docker 1.13 PullImage to convert image and tag to a ref
	//image = strings.TrimSuffix(image, ":")
	//
	//ref, err := reference.ParseNamed(image)
	//if err != nil {
	//	return err
	//}
	//
	//if tag != "" {
	//	// The "tag" could actually be a digest.
	//	var dgst digest.Digest
	//	dgst, err = digest.ParseDigest(tag)
	//	if err == nil {
	//		ref, err = reference.WithDigest(reference.TrimNamed(ref), dgst)
	//	} else {
	//		ref, err = reference.WithTag(ref, tag)
	//	}
	//	if err != nil {
	//		return err
	//	}
	//}
	////*****
	//
	//options := imagec.Options{
	//	Destination: os.TempDir(),
	//	Reference:   ref,
	//	Timeout:     imagec.DefaultHTTPTimeout,
	//	Outstream:   nil,
	//}
	//
	//portLayerServer := v.portlayerAddr
	//if portLayerServer != "" {
	//	options.Host = portLayerServer
	//}
	//
	////ic := imagec.NewImageC(options, streamformatter.NewJSONStreamFormatter())
	//ic := imagec.NewImageC(options, nil)
	//ic.ParseReference()
	//// create url from hostname
	//hostnameURL, err := url.Parse(ic.Registry)
	//if err != nil || hostnameURL.Hostname() == "" {
	//	hostnameURL, err = url.Parse("//" + ic.Registry)
	//	if err != nil {
	//		op.Infof("Error parsing hostname %s during registry access: %s", ic.Registry, err.Error())
	//	}
	//}
	//
	//// Check if url is contained within set of whitelisted or insecure registries
	////regctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	////defer cancel()
	////whitelistOk, _, insecureOk := vchConfig.RegistryCheck(regctx, hostnameURL)
	////if !whitelistOk {
	////	err = fmt.Errorf("Access denied to unauthorized registry (%s) while VCH is in whitelist mode", hostnameURL.Host)
	////	op.Errorf(err.Error())
	////	sf := streamformatter.NewJSONStreamFormatter()
	////	outStream.Write(sf.FormatError(err))
	////	return nil
	////}
	//
	//ic.InsecureAllowHTTP = true
	////ic.InsecureAllowHTTP = insecureOk
	////ic.RegistryCAs = RegistryCertPool
	//
	//ic.Username = username
	//ic.Password = password
	//
	//op.Infof("PullImage: reference: %s, %s, portlayer: %#v",
	//	ic.Reference,
	//	ic.Host,
	//	portLayerServer)
	//
	//err = ic.PullImage()
	//if err != nil {
	//	return err
	//}

	return nil
}
