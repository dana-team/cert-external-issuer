package common

import (
	"context"
	"fmt"

	certyv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getSecretNamespace returns the namespace where the credentials for the issuer are stored.
func getSecretNamespace(issuer client.Object, namespace, clusterResourceNamespace string) (string, error) {
	var secretNamespace string

	switch t := issuer.(type) {
	case *certyv1alpha1.Issuer:
		return namespace, nil
	case *certyv1alpha1.ClusterIssuer:
		return clusterResourceNamespace, nil
	default:
		return secretNamespace, fmt.Errorf("unexpected issuer type: %v", t)
	}
}

// GetSecret returns the secret where the credentials for the issuer exist.
func GetSecret(cl client.Client, ctx context.Context, issuer client.Object, secretName, namespace, clusterResourceNamespace string) (corev1.Secret, error) {
	secret := corev1.Secret{}
	secretNamespace, err := getSecretNamespace(issuer, namespace, clusterResourceNamespace)
	if err != nil {
		return secret, err
	}

	err = cl.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, &secret)
	return secret, err
}
