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

package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/common"
	"github.com/dana-team/cert-external-issuer/internal/issuer/signer"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	defaultHealthCheckInterval  = time.Minute
	eventReasonIssuerReconciler = "IssuerReconciler"
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	HealthCheckerBuilder     signer.HealthCheckerBuilder
	recorder                 record.EventRecorder
}

// +kubebuilder:rbac.yaml:groups=cert.dana.io,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac.yaml:groups=cert.dana.io,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac.yaml:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac.yaml:groups="",resources=events,verbs=create;patch

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	r.recorder = mgr.GetEventRecorderFor(common.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := certv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx).WithValues("Issuer", req.NamespacedName)

	issuer, err := r.newIssuer()
	if err != nil {
		logger.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}

	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Couldn't find Issuer")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Issuer: %v", err)
	}

	issuerSpec, issuerStatus, err := common.GetIssuerSpecAndStatus(issuer)
	if err != nil {
		r.report(logger, issuer, issuerStatus, cmapi.CertificateRequestReasonFailed, "Unable to get the IssuerStatus. Ignoring", err)
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			r.report(logger, issuer, issuerStatus, metav1.ConditionFalse, "Error", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := GetReadyCondition(issuerStatus); ready == nil {
		r.report(logger, issuer, issuerStatus, metav1.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	secret, err := common.GetSecret(r.Client, ctx, issuer, issuerSpec.AuthSecretName, req.Namespace, r.ClusterResourceNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, issuerSpec.AuthSecretName, err)
	}

	checker, err := r.HealthCheckerBuilder(issuerSpec, secret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}

	r.report(logger, issuer, issuerStatus, metav1.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// report gives feedback by updating the Ready Condition of the {Cluster}Issuer
// For added visibility it also logs a message and emits a Kubernetes Event.
func (r *IssuerReconciler) report(logger logr.Logger, issuer client.Object, issuerStatus *certv1alpha1.IssuerStatus, conditionStatus metav1.ConditionStatus, message string, err error) {
	eventType := corev1.EventTypeNormal
	if err != nil {
		logger.Error(err, message)
		eventType = corev1.EventTypeWarning
		message = fmt.Sprintf("%s: %v", message, err)
	} else {
		logger.Info(message)
	}
	r.recorder.Event(issuer, eventType, eventReasonIssuerReconciler, message)
	if SetReadyCondition(issuerStatus, conditionStatus, eventReasonIssuerReconciler, message) {
		logger.Info("Ready Condition changed")
	}
}
