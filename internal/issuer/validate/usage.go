package validate

import (
	"crypto/x509/pkix"
	"fmt"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// validateKeyUsages validates that only supported key usages are specified in the CSR.
func validateKeyUsages(ext pkix.Extension, allowedUsages []string) error {
	keyUsage, err := cmpki.UnmarshalKeyUsage(ext.Value)
	if err != nil {
		return err
	}

	for _, usage := range cmutil.KeyUsageStrings(keyUsage) {
		if !containsString(string(usage), allowedUsages) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.usages", allowedUsages)
		}
	}

	return nil
}

// validateExtKeyUsages validates that only supported extended key usages are specified in the CSR.
func validateExtKeyUsages(ext pkix.Extension, allowedUsages []string) error {
	extKeyUsages, _, err := cmpki.UnmarshalExtKeyUsage(ext.Value)
	if err != nil {
		return err
	}

	for _, usage := range cmutil.ExtKeyUsageStrings(extKeyUsages) {
		if !containsString(string(usage), allowedUsages) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.usages", allowedUsages)
		}
	}

	return nil
}

// convertKeyUsage converts a slice of KeyUsage to a slice of strings.
func convertKeyUsage(usages []cmapi.KeyUsage) []string {
	converted := make([]string, 0, len(usages))

	for _, keyUsage := range usages {
		converted = append(converted, string(keyUsage))
	}

	return converted
}
