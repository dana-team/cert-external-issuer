package validate

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDNSNames(t *testing.T) {
	type params struct {
		dnsNames        []string
		allowedDNSNames bool
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldAllowDNSNamesWhenAllowed": {
			params: params{
				dnsNames:        []string{"example.com"},
				allowedDNSNames: true,
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldNotAllowDNSNamesWhenNotAllowed": {
			params: params{
				dnsNames:        []string{"example.com"},
				allowedDNSNames: false,
			},
			want: want{
				errMsg: fmt.Sprintf(errNotAllowedMsg, ".spec.dnsNames"),
			},
		},
		"ShouldAllowEmptyDNSNamesWhenNotAllowed": {
			params: params{
				dnsNames:        []string{},
				allowedDNSNames: false,
			},
			want: want{
				errMsg: "",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateDNSNames(test.params.dnsNames, test.params.allowedDNSNames)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateIPAddresses(t *testing.T) {
	type params struct {
		ipAddresses        []net.IP
		allowedIPAddresses bool
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldAllowIPAddressesWhenAllowed": {
			params: params{
				ipAddresses:        []net.IP{net.ParseIP("192.168.1.1")},
				allowedIPAddresses: true,
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldNotAllowIPAddressesWhenNotAllowed": {
			params: params{
				ipAddresses:        []net.IP{net.ParseIP("192.168.1.1")},
				allowedIPAddresses: false,
			},
			want: want{
				errMsg: fmt.Sprintf(errNotAllowedMsg, ".spec.ipAddresses"),
			},
		},
		"ShouldAllowEmptyIPAddressesWhenNotAllowed": {
			params: params{
				ipAddresses:        []net.IP{},
				allowedIPAddresses: false,
			},
			want: want{
				errMsg: "",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateIPAddresses(test.params.ipAddresses, test.params.allowedIPAddresses)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateURISANs(t *testing.T) {
	type params struct {
		uris           []*url.URL
		allowedURISANs bool
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldAllowURIsWhenAllowed": {
			params: params{
				uris:           []*url.URL{parseURL("https://example.com")},
				allowedURISANs: true,
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldNotAllowURIsWhenNotAllowed": {
			params: params{
				uris:           []*url.URL{parseURL("https://example.com")},
				allowedURISANs: false,
			},
			want: want{
				errMsg: fmt.Sprintf(errNotAllowedMsg, ".spec.uris"),
			},
		},
		"ShouldAllowEmptyURIsWhenNotAllowed": {
			params: params{
				uris:           []*url.URL{},
				allowedURISANs: false,
			},
			want: want{
				errMsg: "",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateURISANs(test.params.uris, test.params.allowedURISANs)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateEmailSANs(t *testing.T) {
	type params struct {
		emails           []string
		allowedEmailSANs bool
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldAllowEmailSANsWhenAllowed": {
			params: params{
				emails:           []string{"test@example.com"},
				allowedEmailSANs: true,
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldNotAllowEmailSANsWhenNotAllowed": {
			params: params{
				emails:           []string{"test@example.com"},
				allowedEmailSANs: false,
			},
			want: want{
				errMsg: fmt.Sprintf(errNotAllowedMsg, ".spec.emailAddresses"),
			},
		},
		"ShouldAllowEmptyEmailSANsWhenNotAllowed": {
			params: params{
				emails:           []string{},
				allowedEmailSANs: false,
			},
			want: want{
				errMsg: "",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateEmailSANs(test.params.emails, test.params.allowedEmailSANs)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

// parseURL is a helper function which extracts a URL from a string.
func parseURL(rawurl string) *url.URL {
	u, _ := url.Parse(rawurl)
	return u
}
