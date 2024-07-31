package validate

import (
	"fmt"
)

// validateOrganizations validates that only supported organizations are specified in the CSR.
func validateOrganizations(organizations []string, allowedOrganizations []string) error {
	for _, organization := range organizations {
		if !containsString(organization, allowedOrganizations) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.organizations", allowedOrganizations)
		}
	}
	return nil
}

// validateCountries validates that only supported countries are specified in the CSR.
func validateCountries(countries []string, allowedCountries []string) error {
	for _, country := range countries {
		if !containsString(country, allowedCountries) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.countries", allowedCountries)
		}
	}
	return nil
}

// validateOrganizationalUnits validates that only supported organizational units are specified in the CSR.
func validateOrganizationalUnits(units []string, allowedUnits []string) error {
	for _, unit := range units {
		if !containsString(unit, allowedUnits) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.organizationalUnits", allowedUnits)
		}
	}
	return nil
}

// validateLocalities validates that only supported localities are specified in the CSR.
func validateLocalities(localities []string, allowedLocalities []string) error {
	for _, locality := range localities {
		if !containsString(locality, allowedLocalities) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.localities", allowedLocalities)
		}
	}
	return nil
}

// validateProvinces validates that only supported provinces are specified in the CSR.
func validateProvinces(provinces []string, allowedProvinces []string) error {
	for _, province := range provinces {
		if !containsString(province, allowedProvinces) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.provinces", allowedProvinces)
		}
	}
	return nil
}

// validateStreetAddresses validates that only supported street addresses are specified in the CSR.
func validateStreetAddresses(addresses []string, allowedAddresses []string) error {
	for _, address := range addresses {
		if !containsString(address, allowedAddresses) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.streetAddresses", allowedAddresses)
		}
	}
	return nil
}

// validatePostalCodes validates that only supported postal codes are specified in the CSR.
func validatePostalCodes(codes []string, allowedCodes []string) error {
	for _, code := range codes {
		if !containsString(code, allowedCodes) {
			return fmt.Errorf(errAllowedValuesStringMsg, ".spec.subject.postalCodes", allowedCodes)
		}
	}
	return nil
}

// validateSerialNumbers validates that only supported serial numbers are specified in the CSR.
func validateSerialNumbers(serialNumber string, allowedSerialNumbers []string) error {
	if serialNumber != "" && !containsString(serialNumber, allowedSerialNumbers) {
		return fmt.Errorf(errAllowedValuesStringMsg, "allowedSerialNumbers", allowedSerialNumbers)
	}
	return nil
}
