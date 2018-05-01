package containers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"
)

// NewContainerRemoveParams creates a new ContainerRemoveParams object
// with the default values initialized.
func NewContainerRemoveParams() *ContainerRemoveParams {
	var (
		forceDefault = bool(false)
		vDefault     = bool(false)
	)
	return &ContainerRemoveParams{
		Force: &forceDefault,
		V:     &vDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewContainerRemoveParamsWithTimeout creates a new ContainerRemoveParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewContainerRemoveParamsWithTimeout(timeout time.Duration) *ContainerRemoveParams {
	var (
		forceDefault = bool(false)
		vDefault     = bool(false)
	)
	return &ContainerRemoveParams{
		Force: &forceDefault,
		V:     &vDefault,

		timeout: timeout,
	}
}

// NewContainerRemoveParamsWithContext creates a new ContainerRemoveParams object
// with the default values initialized, and the ability to set a context for a request
func NewContainerRemoveParamsWithContext(ctx context.Context) *ContainerRemoveParams {
	var (
		forceDefault = bool(false)
		vDefault     = bool(false)
	)
	return &ContainerRemoveParams{
		Force: &forceDefault,
		V:     &vDefault,

		Context: ctx,
	}
}

// NewContainerRemoveParamsWithHTTPClient creates a new ContainerRemoveParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewContainerRemoveParamsWithHTTPClient(client *http.Client) *ContainerRemoveParams {
	var (
		forceDefault = bool(false)
		vDefault     = bool(false)
	)
	return &ContainerRemoveParams{
		Force:      &forceDefault,
		V:          &vDefault,
		HTTPClient: client,
	}
}

/*ContainerRemoveParams contains all the parameters to send to the API endpoint
for the container remove operation typically these are written to a http.Request
*/
type ContainerRemoveParams struct {

	/*Force*/
	Force *bool
	/*ID*/
	ID string
	/*V*/
	V *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the container remove params
func (o *ContainerRemoveParams) WithTimeout(timeout time.Duration) *ContainerRemoveParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the container remove params
func (o *ContainerRemoveParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the container remove params
func (o *ContainerRemoveParams) WithContext(ctx context.Context) *ContainerRemoveParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the container remove params
func (o *ContainerRemoveParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the container remove params
func (o *ContainerRemoveParams) WithHTTPClient(client *http.Client) *ContainerRemoveParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the container remove params
func (o *ContainerRemoveParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithForce adds the force to the container remove params
func (o *ContainerRemoveParams) WithForce(force *bool) *ContainerRemoveParams {
	o.SetForce(force)
	return o
}

// SetForce adds the force to the container remove params
func (o *ContainerRemoveParams) SetForce(force *bool) {
	o.Force = force
}

// WithID adds the id to the container remove params
func (o *ContainerRemoveParams) WithID(id string) *ContainerRemoveParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the container remove params
func (o *ContainerRemoveParams) SetID(id string) {
	o.ID = id
}

// WithV adds the v to the container remove params
func (o *ContainerRemoveParams) WithV(v *bool) *ContainerRemoveParams {
	o.SetV(v)
	return o
}

// SetV adds the v to the container remove params
func (o *ContainerRemoveParams) SetV(v *bool) {
	o.V = v
}

// WriteToRequest writes these params to a swagger request
func (o *ContainerRemoveParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	r.SetTimeout(o.timeout)
	var res []error

	if o.Force != nil {

		// query param force
		var qrForce bool
		if o.Force != nil {
			qrForce = *o.Force
		}
		qForce := swag.FormatBool(qrForce)
		if qForce != "" {
			if err := r.SetQueryParam("force", qForce); err != nil {
				return err
			}
		}

	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if o.V != nil {

		// query param v
		var qrV bool
		if o.V != nil {
			qrV = *o.V
		}
		qV := swag.FormatBool(qrV)
		if qV != "" {
			if err := r.SetQueryParam("v", qV); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
