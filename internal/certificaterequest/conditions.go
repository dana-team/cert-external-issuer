package certificaterequest

import (
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// IsAlreadyReady returns a boolean indicating whether the CertificateRequest is already Ready based on its conditions.
func IsAlreadyReady(certificateRequest cmapi.CertificateRequest) bool {
	return cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	})
}

// IsAlreadyFailed returns a boolean indicating whether the CertificateRequest is already Failed based on its conditions.
func IsAlreadyFailed(certificateRequest cmapi.CertificateRequest) bool {
	return cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	})
}

// IsAlreadyDenied returns a boolean indicating whether the CertificateRequest is already Denied based on its conditions.
func IsAlreadyDenied(certificateRequest cmapi.CertificateRequest) bool {
	return cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	})
}
