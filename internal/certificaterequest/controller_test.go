package certificaterequest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dana-team/cert-external-issuer/internal/common"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	clock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/issuer/signer"
	"github.com/go-logr/logr"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	certificateRequestNS   = "ns-1"
	certificateRequestName = "cr-1"

	issuerName        = "issuer-1"
	issuerKind        = "Issuer"
	issuerCredentials = issuerName + "-credentials"

	clusterIssuerName        = "cluster-issuer-1"
	clusterIssuerKind        = "ClusterIssuer"
	clusterIssuerCredentials = clusterIssuerName + "-credentials"

	kubeSystemNS  = "kube-system"
	foreignIssuer = "foreign-issuer.example.com"
	foreignKind   = "ForeignKind"
)

var (
	fixedClockStart = time.Date(2021, time.January, 1, 1, 0, 0, 0, time.UTC)
	fixedClock      = clock.NewFakeClock(fixedClockStart)
)

type fakeSigner struct {
	errSign error
}

func (o *fakeSigner) Sign(context.Context, logr.Logger, []byte) ([]byte, []byte, error) {
	return []byte("fake signed certificate"), []byte("fake ca"), o.errSign
}

type args struct {
	name                     types.NamespacedName
	secretObjects            []client.Object
	issuerObjects            []client.Object
	crObjects                []client.Object
	signerBuilder            signer.SignerBuilder
	clusterResourceNamespace string
}
type want struct {
	result               ctrl.Result
	error                error
	readyConditionStatus cmmeta.ConditionStatus
	readyConditionReason string
	failureTime          *metav1.Time
	certificate          []byte
}

func TestReconcile(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)

	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldHandleIssuer": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				secretObjects: []client.Object{&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      issuerCredentials,
						Namespace: certificateRequestNS,
					},
				},
				},
				issuerObjects: []client.Object{&certv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      issuerName,
						Namespace: certificateRequestNS,
					},
					Spec: certv1alpha1.IssuerSpec{
						AuthSecretName: issuerCredentials,
					},
					Status: certv1alpha1.IssuerStatus{
						Conditions: []metav1.Condition{
							{
								Type:   string(cmapi.CertificateRequestConditionReady),
								Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
							},
						},
					},
				},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return &fakeSigner{}, nil
				},
			},
			want: want{
				readyConditionStatus: cmmeta.ConditionTrue,
				readyConditionReason: cmapi.CertificateRequestReasonIssued,
				failureTime:          nil,
				certificate:          []byte("fake signed certificate"),
			},
		},
		"ShouldHandleClusterIssuer": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  clusterIssuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  clusterIssuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				issuerObjects: []client.Object{
					&certv1alpha1.ClusterIssuer{
						ObjectMeta: metav1.ObjectMeta{
							Name: clusterIssuerName,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: clusterIssuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterIssuerCredentials,
						Namespace: kubeSystemNS,
					},
				},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return &fakeSigner{}, nil
				},
				clusterResourceNamespace: kubeSystemNS,
			},
			want: want{
				readyConditionStatus: cmmeta.ConditionTrue,
				readyConditionReason: cmapi.CertificateRequestReasonIssued,
				failureTime:          nil,
				certificate:          []byte("fake signed certificate"),
			},
		},
		"ShouldHandleCertificateRequestNotFound": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
			},
		},
		"ShouldHandleIssuerRefForeignGroup": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: foreignIssuer,
						}),
					),
				},
			},
		},
		"ShouldHandleCertificateRequestAlreadyReady": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionTrue,
						}),
					),
				},
			},
		},
		"ShouldHandleCertificateRequestMissingReadyCondition": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
					),
				},
			},
			want: want{
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleIssuerRefUnknownKind": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  foreignKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
			},
			want: want{
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonFailed,
			},
		},
		"ShouldHandleIssuerNotFound": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
			},
			want: want{
				error:                errGetIssuer,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleClusterIssuerNotFound": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  clusterIssuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  clusterIssuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
			},
			want: want{
				error:                errGetIssuer,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleIssuerNotReady": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionFalse),
								},
							},
						},
					},
				},
			},
			want: want{
				error:                errIssuerNotReady,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleIssuerSecretNotFound": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
			},
			want: want{
				error:                errGetAuthSecret,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleSignerBuilderError": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: certificateRequestNS,
						},
					},
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return nil, errors.New("simulated signer builder error")
				},
			},
			want: want{
				error:                errSignerBuilder,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleSignerError": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionApproved,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: certificateRequestNS,
						},
					},
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return &fakeSigner{errSign: errors.New("simulated sign error")}, nil
				},
			},
			want: want{
				error:                errSignerSign,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonPending,
			},
		},
		"ShouldHandleRequestNotApproved": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestName,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: certificateRequestNS,
						},
					},
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return &fakeSigner{}, nil
				},
			},
			want: want{
				failureTime: nil,
				certificate: nil,
			},
		},
		"ShouldHandleRequestDenied": {
			args: args{
				name: types.NamespacedName{Namespace: certificateRequestNS, Name: certificateRequestName},
				crObjects: []client.Object{
					cmgen.CertificateRequest(
						certificateRequestNS,
						cmgen.SetCertificateRequestNamespace(certificateRequestNS),
						cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
							Name:  issuerName,
							Group: certv1alpha1.GroupVersion.Group,
							Kind:  issuerKind,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionDenied,
							Status: cmmeta.ConditionTrue,
						}),
						cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionUnknown,
						}),
					),
				},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: certificateRequestNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   string(cmapi.CertificateRequestConditionReady),
									Status: metav1.ConditionStatus(cmmeta.ConditionTrue),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "issuer1-credentials",
							Namespace: "ns1",
						},
					},
				},
				signerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (signer.Signer, error) {
					return &fakeSigner{}, nil
				},
			},
			want: want{
				certificate:          nil,
				failureTime:          &nowMetaTime,
				readyConditionStatus: cmmeta.ConditionFalse,
				readyConditionReason: cmapi.CertificateRequestReasonDenied,
			},
		},
	}

	scheme := runtime.NewScheme()
	assert.NoError(t, certv1alpha1.AddToScheme(scheme))
	assert.NoError(t, cmapi.AddToScheme(scheme))
	assert.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			eventRecorder, fakeClient, controller := setupController(scheme, tc.args)
			crBefore := getCertificateRequest(t, fakeClient, tc.args.name)

			result, reconcileErr := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.New(t)),
				reconcile.Request{NamespacedName: tc.args.name},
			)

			actualEvents := common.CollectEvents(eventRecorder)

			if tc.want.error != nil {
				assertErrorIs(t, tc.want.error, reconcileErr)
			} else {
				assert.NoError(t, reconcileErr)
			}
			assert.Equal(t, tc.want.result, result, "Unexpected result")

			crAfter := getCertificateRequest(t, fakeClient, tc.args.name)
			if verifyEmittedEvents(t, crBefore, crAfter, actualEvents) {
				return
			}

			verifyCertificate(t, tc.want.certificate, crAfter.Status.Certificate, tc.want.failureTime, crAfter.Status.FailureTime)
			condition := cmutil.GetCertificateRequestCondition(&crAfter, cmapi.CertificateRequestConditionReady)

			verifyCondition(t, condition, tc.want)
			verifyEvents(t, condition, actualEvents, reconcileErr)
		})
	}
}

// setupController sets up the controller with the fake client.
func setupController(scheme *runtime.Scheme, args args) (*record.FakeRecorder, client.Client, CertificateRequestReconciler) {
	eventRecorder := record.NewFakeRecorder(100)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(args.secretObjects...).
		WithObjects(args.crObjects...).
		WithObjects(args.issuerObjects...).
		WithStatusSubresource(args.issuerObjects...).
		WithStatusSubresource(args.crObjects...).
		Build()

	controller := CertificateRequestReconciler{
		Client:                   fakeClient,
		Scheme:                   scheme,
		ClusterResourceNamespace: args.clusterResourceNamespace,
		SignerBuilder:            args.signerBuilder,
		CheckApprovedCondition:   true,
		Clock:                    fixedClock,
		recorder:                 eventRecorder,
	}
	return eventRecorder, fakeClient, controller
}

// getCertificateRequest returns a CertificateRequest object.
func getCertificateRequest(t *testing.T, fakeClient client.Client, name types.NamespacedName) cmapi.CertificateRequest {
	var cr cmapi.CertificateRequest
	if err := fakeClient.Get(context.TODO(), name, &cr); err != nil {
		assert.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
	}
	return cr
}

// verifyEmittedEvents makes sure that if the CR is unchanged after the Reconcile, then no
// events are emitted. It returns a boolean indicating no further checks should be made.
// NB: controller-runtime FakeClient updates the Resource version.
func verifyEmittedEvents(t *testing.T, crBefore, crAfter cmapi.CertificateRequest, actualEvents []string) bool {
	if crBefore.ResourceVersion == crAfter.ResourceVersion {
		assert.Empty(t, actualEvents, "Events should only be created if the CertificateRequest is modified")
		return true
	}

	return false
}

// verifyCertificate checks the certificate, in case it has been unexpectedly
// set without also having first added and updated the Ready condition.
func verifyCertificate(t *testing.T, expectedCertificate, actualCertificate []byte, expectedFailureTime, actualFailureTime *metav1.Time) {
	assert.Equal(t, expectedCertificate, actualCertificate, "unexpected certificate")

	if !apiequality.Semantic.DeepEqual(expectedFailureTime, actualFailureTime) {
		assert.Equal(t, expectedFailureTime, actualFailureTime, "unexpected failure time")
	}
}

// verifyCondition makes checks if CertificateRequest is expected to have a Ready condition.
func verifyCondition(t *testing.T, condition *cmapi.CertificateRequestCondition, want want) {
	if want.readyConditionStatus != "" {
		if assert.NotNilf(t, condition, "Ready condition was expected but not found: want.readyConditionStatus == %v", want.readyConditionStatus) {
			verifyCertificateRequestReadyCondition(t, want.readyConditionStatus, want.readyConditionReason, condition)
		}
	} else {
		assert.Nil(t, condition, "Unexpected Ready condition")
	}
}

// verifyEvents makes checks to see if expected events have been emitted.
// The desired Event behaviour is as follows: An Event should always be generated when the Ready condition is set;
// Event contents should match the status and message of the condition;
// Event type should be Warning if the Reconcile failed (temporary error);
// Event type should be warning if the condition status is failed (permanent error).
func verifyEvents(t *testing.T, condition *cmapi.CertificateRequestCondition, actualEvents []string, reconcileErr error) {
	if condition == nil {
		assert.Empty(t, actualEvents, "Found unexpected Events without a corresponding Ready condition")
		return
	}

	expectedEventType := corev1.EventTypeNormal
	if reconcileErr != nil || condition.Reason == cmapi.CertificateRequestReasonFailed {
		expectedEventType = corev1.EventTypeWarning
	}

	eventMessage := condition.Message
	if reconcileErr != nil {
		eventMessage = fmt.Sprintf("Error: %v", reconcileErr)
	}

	assert.Equal(t, []string{fmt.Sprintf("%s %s %s", expectedEventType, eventReasonCertificateRequestReconciler, eventMessage)},
		actualEvents, "expected a single event matching the condition",
	)
}

// assertErrorIs verifies the errors.
func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Truef(t, errors.Is(actualError, expectedError), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}

// verifyCertificateRequestReadyCondition verifies the conditions of the Certificate Request.
func verifyCertificateRequestReadyCondition(t *testing.T, status cmmeta.ConditionStatus, reason string, condition *cmapi.CertificateRequestCondition) {
	assert.Equal(t, status, condition.Status, "unexpected condition status")
	validReasons := sets.NewString(
		cmapi.CertificateRequestReasonPending,
		cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued,
		cmapi.CertificateRequestReasonDenied,
	)
	assert.Contains(t, validReasons, reason, "unexpected condition reason")
	assert.Equal(t, reason, condition.Reason, "unexpected condition reason")
}
