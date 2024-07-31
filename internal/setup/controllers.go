package setup

import (
	"errors"
	"fmt"
	"os"

	"github.com/dana-team/cert-external-issuer/internal/certificaterequest"
	"github.com/dana-team/cert-external-issuer/internal/issuer"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/dana-team/cert-external-issuer/internal/issuer/signer"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

var errNotInCluster = errors.New("not running in-cluster")

// Controllers sets up the different controllers with the manager.
func Controllers(mgr manager.Manager, clusterResourceNamespace string, disableApprovedCheck bool) error {
	namespace, err := setClusterResourceNamespace(clusterResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to set cluster resource namespace: %v", err)
	}

	if err := (&issuer.IssuerReconciler{
		Kind:                     "Issuer",
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		ClusterResourceNamespace: namespace,
		HealthCheckerBuilder:     signer.CertSignerHealthCheckerFromIssuerAndSecretData,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create Issuer controller")
	}

	if err := (&issuer.IssuerReconciler{
		Kind:                     "ClusterIssuer",
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		ClusterResourceNamespace: namespace,
		HealthCheckerBuilder:     signer.CertSignerHealthCheckerFromIssuerAndSecretData,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create ClusterIssuer controller")
	}

	if err := (&certificaterequest.CertificateRequestReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		ClusterResourceNamespace: namespace,
		SignerBuilder:            signer.CertSignerFromIssuerAndSecretData,
		CheckApprovedCondition:   !disableApprovedCheck,
		Clock:                    clock.RealClock{},
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create CertificateRequest controller")
	}

	return nil
}

// setClusterResourceNamespace returns the value of the ClusterResourceNamespace.
func setClusterResourceNamespace(clusterResourceNamespace string) (string, error) {
	var err error
	namespace := clusterResourceNamespace

	if clusterResourceNamespace == "" {
		namespace, err = getInClusterNamespace()
		if err != nil {
			if errors.Is(err, errNotInCluster) {
				return namespace, fmt.Errorf("please supply --cluster-resource-namespace: %v", err)
			} else {
				return namespace, fmt.Errorf("unexpected error while getting in-cluster Namespace: %v", err)
			}
		}
	}

	return namespace, err
}

// getInClusterNamespace returns the name of the namespace where the pod is currently running
// Copied from controller-runtime/pkg/leaderelection.
func getInClusterNamespace() (string, error) {
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return "", errors.New("not running in-cluster")
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}
