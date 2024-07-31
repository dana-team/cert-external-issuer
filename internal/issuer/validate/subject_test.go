package validate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateOrganizations(t *testing.T) {
	type params struct {
		organizations        []string
		allowedOrganizations []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidOrganization": {
			params: params{
				organizations:        []string{"ValidOrg"},
				allowedOrganizations: []string{"ValidOrg"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidOrganization": {
			params: params{
				organizations:        []string{"InvalidOrg"},
				allowedOrganizations: []string{"ValidOrg"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.organizations", []string{"ValidOrg"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateOrganizations(test.params.organizations, test.params.allowedOrganizations)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateCountries(t *testing.T) {
	type params struct {
		countries        []string
		allowedCountries []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidCountry": {
			params: params{
				countries:        []string{"US"},
				allowedCountries: []string{"US"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidCountry": {
			params: params{
				countries:        []string{"FR"},
				allowedCountries: []string{"US"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.countries", []string{"US"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateCountries(test.params.countries, test.params.allowedCountries)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateOrganizationalUnits(t *testing.T) {
	type params struct {
		units        []string
		allowedUnits []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidOrganizationalUnit": {
			params: params{
				units:        []string{"ValidUnit"},
				allowedUnits: []string{"ValidUnit"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidOrganizationalUnit": {
			params: params{
				units:        []string{"InvalidUnit"},
				allowedUnits: []string{"ValidUnit"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.organizationalUnits", []string{"ValidUnit"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateOrganizationalUnits(test.params.units, test.params.allowedUnits)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateLocalities(t *testing.T) {
	type params struct {
		localities        []string
		allowedLocalities []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidLocality": {
			params: params{
				localities:        []string{"ValidLocality"},
				allowedLocalities: []string{"ValidLocality"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidLocality": {
			params: params{
				localities:        []string{"InvalidLocality"},
				allowedLocalities: []string{"ValidLocality"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.localities", []string{"ValidLocality"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateLocalities(test.params.localities, test.params.allowedLocalities)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateProvinces(t *testing.T) {
	type params struct {
		provinces        []string
		allowedProvinces []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidProvince": {
			params: params{
				provinces:        []string{"ValidProvince"},
				allowedProvinces: []string{"ValidProvince"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidProvince": {
			params: params{
				provinces:        []string{"InvalidProvince"},
				allowedProvinces: []string{"ValidProvince"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.provinces", []string{"ValidProvince"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateProvinces(test.params.provinces, test.params.allowedProvinces)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidateStreetAddresses(t *testing.T) {
	type params struct {
		addresses        []string
		allowedAddresses []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidStreetAddress": {
			params: params{
				addresses:        []string{"123 Valid St"},
				allowedAddresses: []string{"123 Valid St"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidStreetAddress": {
			params: params{
				addresses:        []string{"123 Invalid St"},
				allowedAddresses: []string{"123 Valid St"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.streetAddresses", []string{"123 Valid St"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateStreetAddresses(test.params.addresses, test.params.allowedAddresses)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}

func TestValidatePostalCodes(t *testing.T) {
	type params struct {
		codes        []string
		allowedCodes []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidPostalCode": {
			params: params{
				codes:        []string{"12345"},
				allowedCodes: []string{"12345"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidPostalCode": {
			params: params{
				codes:        []string{"54321"},
				allowedCodes: []string{"12345"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.postalCodes", []string{"12345"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := validatePostalCodes(test.params.codes, test.params.allowedCodes)
			if err != nil {
				assert.Equal(t, test.want.errMsg, err.Error())
			} else {
				assert.Empty(t, test.want.errMsg)
			}
		})
	}
}
