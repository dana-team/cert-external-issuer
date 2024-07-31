package issuer

import (
	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// conditionReady represents the fact that a given Issuer condition
// is in ready state and able to issue certificates.
// If the `status` of this condition is `False`, CertificateRequest controllers
// should prevent attempts to sign certificates.
const conditionReady string = "Ready"

// SetReadyCondition sets a Ready condition.
func SetReadyCondition(status *certv1alpha1.IssuerStatus, conditionStatus metav1.ConditionStatus, reason, message string) bool {
	newCondition := metav1.Condition{
		Type:    conditionReady,
		Status:  conditionStatus,
		Reason:  reason,
		Message: message,
	}

	return apimeta.SetStatusCondition(&status.Conditions, newCondition)
}

// GetReadyCondition returns the Ready condition from status.
func GetReadyCondition(status *certv1alpha1.IssuerStatus) *metav1.Condition {
	return apimeta.FindStatusCondition(status.Conditions, conditionReady)
}

// IsReady returns whether an Issuer is ready based on its Condition
func IsReady(status *certv1alpha1.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == metav1.ConditionTrue
	}
	return false
}
