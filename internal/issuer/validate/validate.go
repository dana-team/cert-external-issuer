package validate

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
)

const (
	errValidationFailedMsg    = "%s validation failed: %v"
	errAllowedValuesStringMsg = "the only allowed values for %q in the Certificate are %q"
	errAllowedValuesIntMsg    = "the only allowed values for %q in the Certificate are %d"
	errNotAllowedMsg          = "%s is not allowed to be set in the Certificate"
)

var (
	keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}
	extUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// EnsureCSR makes sures that the CSR complies with the restrictions of the Cert API.
func EnsureCSR(csr *x509.CertificateRequest, restrictions certv1alpha1.Restrictions) error {
	if err := validateKey(csr, restrictions.PrivateKeyRestrictions); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "key", err)
	}

	if err := validateSubjectAltName(csr, restrictions.SubjectAltNamesRestrictions); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "subjectAltName", err)
	}

	if err := validateSubject(csr, restrictions.SubjectRestrictions); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "subject", err)
	}

	if err := validateUsages(csr, restrictions.UsageRestrictions); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "usage", err)
	}

	if err := validateDomain(csr, restrictions.DomainRestrictions); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "domain", err)
	}

	return nil
}

// validateKey validates the key type and size specified in the CSR against the private key restrictions.
func validateKey(csr *x509.CertificateRequest, privateKeyRestrictions certv1alpha1.PrivateKeyRestrictions) error {
	if len(privateKeyRestrictions.AllowedPrivateKeyAlgorithms) == 0 {
		return nil
	}

	allowedAlgorithms := convertPrivateKeyAlgorithm(privateKeyRestrictions.AllowedPrivateKeyAlgorithms)

	if err := validateKeyType(csr, allowedAlgorithms); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "type", err)
	}

	if err := validateKeySize(csr, privateKeyRestrictions.AllowedPrivateKeySizes); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "size", err)
	}

	return nil
}

// validateSubjectAltName validates the subject alternative names in the CSR against the restrictions.
func validateSubjectAltName(csr *x509.CertificateRequest, subjectAltNamesRestrictions certv1alpha1.SubjectAltNamesRestrictions) error {
	if err := validateDNSNames(csr.DNSNames, subjectAltNamesRestrictions.AllowDNSNames); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "dnsName", err)
	}

	if err := validateIPAddresses(csr.IPAddresses, subjectAltNamesRestrictions.AllowIPAddresses); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "ipAddress", err)
	}

	if err := validateURISANs(csr.URIs, subjectAltNamesRestrictions.AllowURISANs); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "uriSANs", err)
	}

	if err := validateEmailSANs(csr.EmailAddresses, subjectAltNamesRestrictions.AllowEmailSANs); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "emailSANs", err)
	}

	return nil
}

// validateSubject validates the subject of the given certificate request against the subject restrictions.
func validateSubject(csr *x509.CertificateRequest, subjectRestrictions certv1alpha1.SubjectRestrictions) error {
	if len(subjectRestrictions.AllowedOrganizations) > 0 {
		if err := validateOrganizations(csr.Subject.Organization, subjectRestrictions.AllowedOrganizations); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "organization", err)
		}
	}

	if len(subjectRestrictions.AllowedCountries) > 0 {
		if err := validateCountries(csr.Subject.Country, subjectRestrictions.AllowedCountries); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "country", err)
		}
	}

	if len(subjectRestrictions.AllowedOrganizationalUnits) > 0 {
		if err := validateOrganizationalUnits(csr.Subject.OrganizationalUnit, subjectRestrictions.AllowedOrganizationalUnits); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "organizational unit", err)
		}
	}

	if len(subjectRestrictions.AllowedLocalities) > 0 {
		if err := validateLocalities(csr.Subject.Locality, subjectRestrictions.AllowedLocalities); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "locality", err)
		}
	}

	if len(subjectRestrictions.AllowedProvinces) > 0 {
		if err := validateProvinces(csr.Subject.Province, subjectRestrictions.AllowedProvinces); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "province", err)
		}
	}

	if len(subjectRestrictions.AllowedStreetAddresses) > 0 {
		if err := validateStreetAddresses(csr.Subject.StreetAddress, subjectRestrictions.AllowedStreetAddresses); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "street address", err)
		}
	}

	if len(subjectRestrictions.AllowedPostalCodes) > 0 {
		if err := validatePostalCodes(csr.Subject.PostalCode, subjectRestrictions.AllowedPostalCodes); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "postal code", err)
		}
	}

	if len(subjectRestrictions.AllowedSerialNumbers) > 0 {
		if err := validateSerialNumbers(csr.Subject.SerialNumber, subjectRestrictions.AllowedSerialNumbers); err != nil {
			return fmt.Errorf(errValidationFailedMsg, "serial number", err)
		}
	}

	return nil
}

// validateUsages validates the key usages specified in the CSR against the usage restrictions.
func validateUsages(csr *x509.CertificateRequest, usageRestrictions certv1alpha1.UsageRestrictions) error {
	if len(usageRestrictions.AllowedUsages) == 0 {
		return nil
	}

	allowedUsages := convertKeyUsage(usageRestrictions.AllowedUsages)

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(keyUsageOID) {
			if err := validateKeyUsages(ext, allowedUsages); err != nil {
				return fmt.Errorf(errValidationFailedMsg, "key usages", err)
			}
		} else if ext.Id.Equal(extUsageOID) {
			if err := validateExtKeyUsages(ext, allowedUsages); err != nil {
				return fmt.Errorf(errValidationFailedMsg, "extended key usages", err)
			}
		}
	}

	return nil
}

// validateSubject validates the domain of the given certificate request against the domain restrictions.
func validateDomain(csr *x509.CertificateRequest, domainRestrictions certv1alpha1.DomainRestrictions) error {
	if err := validateNameDomain([]string{csr.Subject.CommonName}, domainRestrictions.AllowedDomains, domainRestrictions.AllowedSubdomains); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "commonName", err)
	}

	if err := validateNameDomain(csr.DNSNames, domainRestrictions.AllowedDomains, domainRestrictions.AllowedSubdomains); err != nil {
		return fmt.Errorf(errValidationFailedMsg, "dnsNames", err)
	}

	return nil
}
