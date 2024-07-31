package common

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
)

// GetIssuerSpecAndStatus returns the spec and status of an Issuer or ClusterIssuer.
func GetIssuerSpecAndStatus(issuer client.Object) (*certv1alpha1.IssuerSpec, *certv1alpha1.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *certv1alpha1.Issuer:
		return &t.Spec, &t.Status, nil
	case *certv1alpha1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}
