package validate

import (
	"fmt"
)

// validateNameDomain checks if the given names match the allowed domains and allowed subdomains.
func validateNameDomain(names []string, allowedDomains, allowedSubDomains []string) error {
	for _, name := range names {
		for _, domain := range allowedDomains {
			if !hasSuffix(name, domain) {
				return fmt.Errorf(errAllowedValuesStringMsg, ".spec.commonName domain", allowedDomains)
			}
		}

		for _, subdomain := range allowedSubDomains {
			if !hasSuffix(name, subdomain) {
				return fmt.Errorf(errAllowedValuesStringMsg, ".spec.commonName subdomain", allowedSubDomains)
			}
		}
	}

	return nil
}
