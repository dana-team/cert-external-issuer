package validate

import (
	"fmt"
	"net"
	"net/url"
)

// validateDNSNames validates that only allowed DNS names are specified in the CSR.
func validateDNSNames(dnsNames []string, allowedDNSNames bool) error {
	if !allowedDNSNames && len(dnsNames) > 0 {
		return fmt.Errorf(errNotAllowedMsg, ".spec.dnsNames")
	}
	return nil
}

// validateIPAddresses validates that only allowed IP addresses are specified in the CSR.
func validateIPAddresses(ipAddresses []net.IP, allowedIPAddresses bool) error {
	if !allowedIPAddresses && len(ipAddresses) > 0 {
		return fmt.Errorf(errNotAllowedMsg, ".spec.ipAddresses")
	}
	return nil
}

// validateURISANs validates that only allowed URIs are specified in the CSR.
func validateURISANs(uris []*url.URL, allowedURISANs bool) error {
	if !allowedURISANs && len(uris) > 0 {
		return fmt.Errorf(errNotAllowedMsg, ".spec.uris")
	}
	return nil
}

// validateEmailSANs validates that only allowed email SANs are specified in the CSR.
func validateEmailSANs(emails []string, allowedEmailSANs bool) error {
	if !allowedEmailSANs && len(emails) > 0 {
		return fmt.Errorf(errNotAllowedMsg, ".spec.emailAddresses")
	}
	return nil
}
