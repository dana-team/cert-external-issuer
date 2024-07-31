package issuer

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/common"
	"github.com/dana-team/cert-external-issuer/internal/issuer/signer"
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	issuerNS = "ns-1"

	issuerName        = "issuer-1"
	issuerKind        = "Issuer"
	issuerCredentials = issuerName + "-credentials"

	clusterIssuerName        = "cluster-issuer-1"
	clusterIssuerKind        = "ClusterIssuer"
	clusterIssuerCredentials = clusterIssuerName + "-credentials"

	kubeSystemNS     = "kube-system"
	unrecognizedKind = "UnrecognizedKind"
)

type fakeHealthChecker struct {
	errCheck error
}

func (o *fakeHealthChecker) Check() error {
	return o.errCheck
}

type args struct {
	kind                     string
	name                     types.NamespacedName
	issuerObjects            []client.Object
	secretObjects            []client.Object
	healthCheckerBuilder     signer.HealthCheckerBuilder
	clusterResourceNamespace string
}

type want struct {
	result               ctrl.Result
	error                error
	readyConditionStatus metav1.ConditionStatus
}

func TestIssuerReconcile(t *testing.T) {
	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldHandleIssuer": {
			args: args{
				kind: issuerKind,
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: issuerNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   conditionReady,
									Status: metav1.ConditionStatus(cmmeta.ConditionUnknown),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: issuerNS,
						},
					},
				},
				healthCheckerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte) (signer.HealthChecker, error) {
					return &fakeHealthChecker{}, nil
				},
			},
			want: want{
				readyConditionStatus: metav1.ConditionTrue,
				result:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
			},
		},
		"ShouldHandleClusterIssuer": {
			args: args{
				kind: clusterIssuerKind,
				name: types.NamespacedName{Name: clusterIssuerName},
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
									Type:   conditionReady,
									Status: metav1.ConditionStatus(cmmeta.ConditionUnknown),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      clusterIssuerCredentials,
							Namespace: kubeSystemNS,
						},
					},
				},
				healthCheckerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte) (signer.HealthChecker, error) {
					return &fakeHealthChecker{}, nil
				},
				clusterResourceNamespace: kubeSystemNS,
			},
			want: want{
				readyConditionStatus: metav1.ConditionTrue,
				result:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
			},
		},
		"ShouldHandleUnrecognizedKind": {
			args: args{
				kind: unrecognizedKind,
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
			},
		},
		"ShouldHandleIssuerNotFound": {
			args: args{
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
			},
		},
		"ShouldHandleMissingReadyCondition": {
			args: args{
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: issuerNS,
						},
					},
				},
			},
			want: want{
				readyConditionStatus: metav1.ConditionUnknown,
			},
		},
		"ShouldHandleMissingSecret": {
			args: args{
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: issuerNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   conditionReady,
									Status: metav1.ConditionStatus(cmmeta.ConditionUnknown),
								},
							},
						},
					},
				},
			},
			want: want{
				error:                errGetAuthSecret,
				readyConditionStatus: metav1.ConditionFalse,
			},
		},
		"ShouldHandleFailingHealthCheckerBuilder": {
			args: args{
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: issuerNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   conditionReady,
									Status: metav1.ConditionStatus(cmmeta.ConditionUnknown),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: issuerNS,
						},
					},
				},
				healthCheckerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte) (signer.HealthChecker, error) {
					return nil, errors.New("simulated health checker builder error")
				},
			},
			want: want{
				error:                errHealthCheckerBuilder,
				readyConditionStatus: metav1.ConditionFalse,
			},
		},
		"ShouldHandleFailingHealthCheckerCheck": {
			args: args{
				name: types.NamespacedName{Namespace: issuerNS, Name: issuerName},
				issuerObjects: []client.Object{
					&certv1alpha1.Issuer{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerName,
							Namespace: issuerNS,
						},
						Spec: certv1alpha1.IssuerSpec{
							AuthSecretName: issuerCredentials,
						},
						Status: certv1alpha1.IssuerStatus{
							Conditions: []metav1.Condition{
								{
									Type:   conditionReady,
									Status: metav1.ConditionStatus(cmmeta.ConditionUnknown),
								},
							},
						},
					},
				},
				secretObjects: []client.Object{
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      issuerCredentials,
							Namespace: issuerNS,
						},
					},
				},
				healthCheckerBuilder: func(*certv1alpha1.IssuerSpec, map[string][]byte) (signer.HealthChecker, error) {
					return &fakeHealthChecker{errCheck: errors.New("simulated health check error")}, nil
				},
			},
			want: want{
				error:                errHealthCheckerCheck,
				readyConditionStatus: metav1.ConditionFalse,
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
			issuerBefore := getIssuer(t, fakeClient, tc.args.name, controller)

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

			issuerAfter := getIssuer(t, fakeClient, tc.args.name, controller)
			if issuerAfter == nil {
				return
			}

			if verifyEmittedEvents(t, issuerBefore, issuerAfter, actualEvents) {
				return
			}

			_, issuerStatusAfter, err := common.GetIssuerSpecAndStatus(issuerAfter)
			require.NoError(t, err)
			condition := GetReadyCondition(issuerStatusAfter)
			verifyCondition(t, *condition, tc.want)
			verifyEvents(t, condition, actualEvents, reconcileErr)
		})
	}
}

// setupController sets up the controller with the fake client.
func setupController(scheme *runtime.Scheme, args args) (*record.FakeRecorder, client.Client, IssuerReconciler) {
	eventRecorder := record.NewFakeRecorder(100)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(args.secretObjects...).
		WithObjects(args.issuerObjects...).
		WithStatusSubresource(args.issuerObjects...).
		Build()
	if args.kind == "" {
		args.kind = issuerKind
	}

	controller := IssuerReconciler{
		Kind:                     args.kind,
		Client:                   fakeClient,
		Scheme:                   scheme,
		HealthCheckerBuilder:     args.healthCheckerBuilder,
		ClusterResourceNamespace: args.clusterResourceNamespace,
		recorder:                 eventRecorder,
	}

	return eventRecorder, fakeClient, controller
}

// getIssuer returns an Issuer object.
func getIssuer(t *testing.T, fakeClient client.Client, name types.NamespacedName, controller IssuerReconciler) client.Object {
	issuer, err := controller.newIssuer()

	if err == nil {
		if err := fakeClient.Get(context.TODO(), name, issuer); err != nil {
			assert.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
		}
	}

	return issuer
}

// verifyEmittedEvents makes sure that if the CR is unchanged after the Reconcile, then no
// events are emitted. It returns a boolean indicating no further checks should be made.
// NB: controller-runtime FakeClient updates the Resource version.
func verifyEmittedEvents(t *testing.T, issuerBefore, issuerAfter client.Object, actualEvents []string) bool {
	if issuerBefore.GetResourceVersion() == issuerAfter.GetResourceVersion() {
		assert.Empty(t, actualEvents, "Events should only be created if the {Cluster}Issuer is modified")
		return true
	}

	return false
}

// verifyCondition makes checks if Issuer is expected to have a Ready condition.
func verifyCondition(t *testing.T, condition metav1.Condition, want want) {
	if want.readyConditionStatus != "" {
		if assert.NotNilf(t, condition, "Ready condition was expected but not found: want.readyConditionStatus == %v", want.readyConditionStatus) {
			verifyIssuerReadyCondition(t, want.readyConditionStatus, condition)
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
func verifyEvents(t *testing.T, condition *metav1.Condition, actualEvents []string, reconcileErr error) {
	if condition == nil {
		assert.Empty(t, actualEvents, "Found unexpected Events without a corresponding Ready condition")
		return
	}

	expectedEventType := corev1.EventTypeNormal
	if reconcileErr != nil || condition.Status == metav1.ConditionFalse {
		expectedEventType = corev1.EventTypeWarning
	}

	eventMessage := condition.Message
	if reconcileErr != nil {
		eventMessage = fmt.Sprintf("Error: %v", reconcileErr)
	}

	assert.Equal(t, []string{fmt.Sprintf("%s %s %s", expectedEventType, eventReasonIssuerReconciler, eventMessage)},
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

func verifyIssuerReadyCondition(t *testing.T, status metav1.ConditionStatus, condition metav1.Condition) {
	assert.Equal(t, status, condition.Status, "unexpected condition status")
}
