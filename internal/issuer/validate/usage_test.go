package validate

import (
	"crypto/x509"
	"fmt"
	"testing"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/stretchr/testify/assert"
)

func TestValidateKeyUsages(t *testing.T) {
	type params struct {
		usage         x509.KeyUsage
		allowedUsages []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidKeyUsage": {
			params: params{
				usage:         x509.KeyUsageDigitalSignature,
				allowedUsages: []string{"digital signature"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidKeyUsage": {
			params: params{
				usage:         x509.KeyUsageDigitalSignature,
				allowedUsages: []string{"key encipherment"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.usages", []string{"key encipherment"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			ext, err := cmpki.MarshalKeyUsage(test.params.usage)
			assert.NoError(t, err)

			err = validateKeyUsages(ext, test.params.allowedUsages)
			if test.want.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.want.errMsg)
			}
		})
	}
}

func TestValidateExtKeyUsages(t *testing.T) {
	type params struct {
		usages        []x509.ExtKeyUsage
		allowedUsages []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldAllowValidExtKeyUsages": {
			params: params{
				usages:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				allowedUsages: []string{"server auth", "client auth"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldNotAllowInvalidExtKeyUsages": {
			params: params{
				usages:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				allowedUsages: []string{"email protection", "code signing"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.usages", []string{"email protection", "code signing"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			ext, err := cmpki.MarshalExtKeyUsage(test.params.usages, nil)
			assert.NoError(t, err)

			err = validateExtKeyUsages(ext, test.params.allowedUsages)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}
