package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/validate"
)

// StoreURL store Url
// swagger:model StoreUrl
type StoreURL struct {

	// code
	Code int64 `json:"code,omitempty"`

	// url
	// Required: true
	URL string `json:"url"`
}

// Validate validates this store Url
func (m *StoreURL) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateURL(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *StoreURL) validateURL(formats strfmt.Registry) error {

	if err := validate.RequiredString("url", "body", string(m.URL)); err != nil {
		return err
	}

	return nil
}
