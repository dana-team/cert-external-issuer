package validate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateNameDomain(t *testing.T) {
	type params struct {
		names             []string
		allowedDomains    []string
		allowedSubDomains []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidDomain": {
			params: params{
				names:          []string{"example.com"},
				allowedDomains: []string{"example.com"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidDomain": {
			params: params{
				names:          []string{"invalid.com"},
				allowedDomains: []string{"example.com"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName domain", []string{"example.com"}),
			},
		},
		"ShouldSucceedWithValidSubdomain": {
			params: params{
				names:             []string{"sub.example.com"},
				allowedSubDomains: []string{"sub.example.com"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidSubdomain": {
			params: params{
				names:             []string{"sub.invalid.com"},
				allowedSubDomains: []string{"sub.example.com"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName subdomain", []string{"sub.example.com"}),
			},
		},
		"ShouldFailWithInvalidDomainAndValidSubdomain": {
			params: params{
				names:             []string{"invalid.com", "sub.example.com"},
				allowedDomains:    []string{"example.com"},
				allowedSubDomains: []string{"sub.example.com"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName domain", []string{"example.com"}),
			},
		},
		"ShouldFailWithValidDomainAndInvalidSubdomain": {
			params: params{
				names:             []string{"example.com", "sub.invalid.com"},
				allowedDomains:    []string{"example.com"},
				allowedSubDomains: []string{"sub.example.com"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName subdomain", []string{"sub.example.com"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateNameDomain(test.params.names, test.params.allowedDomains, test.params.allowedSubDomains)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			}
		})
	}
}
