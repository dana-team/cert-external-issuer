/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer.
type IssuerSpec struct {
	// APIEndpoint is the base URL for the endpoint of the Cert API service.
	APIEndpoint string `json:"apiEndpoint"`

	// APIEndpoint is the download URL for the endpoint of the Cert API service.
	DownloadEndpoint string `json:"downloadEndpoint"`

	// Form is the format of the Certificate that is downloaded from the Cert API service.
	// +kubebuilder:default:="chain"
	// +kubebuilder:validation:Enum=chain;public
	Form string `json:"form,omitempty"`

	// AuthSecretName is a reference to a Secret in the same namespace as the referent. If the
	// referent is a ClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	AuthSecretName string `json:"authSecretName"`

	// HTTPConfig specifies configuration relating to the HTTP client used to interact
	// with the cert API.
	HTTPConfig HTTPConfig `json:"httpConfig"`

	// CertificateRestrictions is a set of restrictions for a Certificate imposed by the Issuer.
	CertificateRestrictions Restrictions `json:"certificateRestrictions,omitempty"`
}

type HTTPConfig struct {
	// SkipVerifyTLS specifies whether to skip TLS verification in HTTP requests.
	SkipVerifyTLS bool `json:"skipVerifyTLS"`

	// WaitTimeout specifies the maximum time duration for waiting for response in HTTP requests.
	WaitTimeout *metav1.Duration `json:"waitTimeout,omitempty"`

	// RetryBackoff specifies the retry configuration in HTTP requests.
	RetryBackoff RetryBackoff `json:"retryBackoff,omitempty"`
}

// RetryBackoff specifies the retry configuration in HTTP requests.
// It is the wait.Backoff but with json tags.
type RetryBackoff struct {
	// Duration is the initial duration.
	Duration metav1.Duration `json:"duration,omitempty"`

	// Factor multiplies duration in each iteration, if factor is not zero
	// and the limits imposed by Steps. Should not be negative.
	Factor string `json:"factor,omitempty"`

	// Jitter contributes to the sleep at each iteration. It is
	// the duration plus an additional amount chosen uniformly at
	// random from the interval between zero and `jitter*duration`.
	Jitter string `json:"jitter,omitempty"`

	// Steps is the remaining number of iterations in which the duration
	// parameter may change. If not positive, the duration is not
	// changed. Used for exponential backoff in combination with Factor.
	Steps int `json:"steps,omitempty"`
}

// Restrictions defines a set of restrictions for a Certificate imposed by the Issuer.
type Restrictions struct {
	// PrivateKeyRestrictions represents the PrivateKey restrictions imposed by the Issuer.
	// +optional
	PrivateKeyRestrictions PrivateKeyRestrictions `json:"privateKeyRestrictions,omitempty"`

	// SubjectRestrictions represents the Subject restrictions imposed by the Issuer.
	// +optional
	SubjectRestrictions SubjectRestrictions `json:"subjectRestrictions,omitempty"`

	// UsageRestrictions represents the Usages restrictions imposed by the Issuer.
	// +optional
	UsageRestrictions UsageRestrictions `json:"usageRestrictions,omitempty"`

	// DomainRestrictions represents the Domain restrictions imposed by the Issuer.
	// +optional
	DomainRestrictions DomainRestrictions `json:"domainRestrictions,omitempty"`

	// SubjectAltNamesRestrictions represents the SubjectAltNames restrictions imposed by the Issuer.
	// +optional
	SubjectAltNamesRestrictions SubjectAltNamesRestrictions `json:"subjectAltNamesRestrictions,omitempty"`
}

// PrivateKeyRestrictions represents the PrivateKey restrictions imposed by the Issuer.
type PrivateKeyRestrictions struct {
	// AllowedPrivateKeyAlgorithms is a set of private key algorithms of the
	// corresponding private key for a Certificate which is supported by the Issuer.
	// +optional
	AllowedPrivateKeyAlgorithms []cmapi.PrivateKeyAlgorithm `json:"allowedPrivateKeyAlgorithms,omitempty"`

	// AllowedPrivateKeySizes is a set of key bit sizes of the
	// corresponding private key for a Certificate which is supported by the Issuer.
	// +optional
	AllowedPrivateKeySizes []int `json:"allowedPrivateKeySizes,omitempty"`
}

// SubjectRestrictions represents the Subject restrictions imposed by the Issuer.
type SubjectRestrictions struct {
	// AllowedOrganizations is a set of Organizations that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedOrganizations []string `json:"allowedOrganizations,omitempty"`

	// AllowedCountries is a set of Countries that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedCountries []string `json:"allowedCountries,omitempty"`

	// AllowedOrganizationalUnits is a set of OrganizationalUnits that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedOrganizationalUnits []string `json:"allowedOrganizationalUnits,omitempty"`

	// AllowedLocalities is a set of Localities that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedLocalities []string `json:"allowedLocalities,omitempty"`

	// AllowedProvinces is a set of Provinces that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedProvinces []string `json:"allowedProvinces,omitempty"`

	// AllowedStreetAddresses is a set of StreetAddresses that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedStreetAddresses []string `json:"allowedStreetAddresses,omitempty"`

	// AllowedPostalCodes is a set of PostalCodes that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedPostalCodes []string `json:"allowedPostalCodes,omitempty"`

	// AllowedSerialNumbers is a set of SerialNumbers that can be used on a Certificate and are supported by the Issuer.
	// +optional
	AllowedSerialNumbers []string `json:"allowedSerialNumbers,omitempty"`
}

// UsageRestrictions represents the Usage restrictions imposed by the Issuer.
type UsageRestrictions struct {
	// AllowedUsages is a set of x509 usages that are requested for a Certificate
	// and are supported by the Issuer.
	// +optional
	AllowedUsages []cmapi.KeyUsage `json:"allowedUsages,omitempty"`
}

// DomainRestrictions represents the Domain restrictions imposed by the Issuer.
type DomainRestrictions struct {
	// AllowedDomains is a set of domains that are used on a Certificate
	// and are supported by the Issuer.
	// +optional
	AllowedDomains []string `json:"allowedDomains,omitempty"`

	// AllowedSubdomains is a set of Subdomains that are used on a Certificate
	// and are supported by the Issuer.
	// +optional
	AllowedSubdomains []string `json:"allowedSubdomains,omitempty"`
}

// SubjectAltNamesRestrictions represents the SubjectAltNames restrictions imposed by the Issuer.
type SubjectAltNamesRestrictions struct {
	// AllowDNSNames is a boolean indicating whether specifying DNSNames on the Certificate is allowed by the Issuer.
	AllowDNSNames bool `json:"allowDNSNames,omitempty"`

	// AllowIPAddresses is a boolean indicating whether specifying IPAddresses on the Certificate is allowed by the Issuer.
	AllowIPAddresses bool `json:"allowIPAddresses,omitempty"`

	// AllowedAllowedURISANs is a boolean indicating whether specifying URISANs on the Certificate is allowed by the Issuer.
	AllowURISANs bool `json:"allowAllowedURISANs,omitempty"`

	// AllowEmailSANs is a boolean indicating whether specifying EmailSANs on the Certificate is allowed by the Issuer.
	AllowEmailSANs bool `json:"allowAllowedEmailSANs,omitempty"`
}

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
