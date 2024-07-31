package certificaterequest

import (
	"context"
	"errors"
	"fmt"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/dana-team/cert-external-issuer/internal/common"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/issuer"
	certsigner "github.com/dana-team/cert-external-issuer/internal/issuer/signer"
)

const (
	eventReasonCertificateRequestReconciler = "CertificateRequestReconciler"
)

var (
	errGetCertificateRequest = errors.New("error getting CertificateRequest")
	errGetIssuer             = errors.New("error getting Issuer")
	errUnrecognisedKind      = errors.New("unrecognised kind")
	errIssuerNotReady        = errors.New("issuer is not ready")
	errGetAuthSecret         = errors.New("failed to get Secret containing Issuer credentials")
	errSignerBuilder         = errors.New("failed to build the Signer")
	errSignerSign            = errors.New("failed to sign")
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	SignerBuilder            certsigner.SignerBuilder
	Clock                    clock.Clock
	recorder                 record.EventRecorder
	CheckApprovedCondition   bool
	ClusterResourceNamespace string
}

// +kubebuilder:rbac.yaml:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac.yaml:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac.yaml:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac.yaml:groups="",resources=events,verbs=create;patch

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(common.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx).WithValues("CertificateRequest", req.NamespacedName)

	certificateRequest := cmapi.CertificateRequest{}
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Couldn't find CertificateRequest")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetCertificateRequest, err)
	}

	if r.ignore(logger, certificateRequest) {
		return ctrl.Result{}, nil
	}

	// always attempt to update the Ready condition
	defer func() {
		if err != nil {
			r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonPending, "Error", err)
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		logger.Info("CertificateRequest has been denied. Marking as failed.")
		r.markAsDenied(logger, certificateRequest)
		return ctrl.Result{}, nil
	}

	if r.initializeReadyCondition(logger, &certificateRequest) {
		return ctrl.Result{}, nil
	}

	issuerInstance, err := r.getIssuer(logger, ctx, certificateRequest)
	if err != nil {
		if errors.Is(err, errUnrecognisedKind) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	issuerSpec, issuerStatus, err := common.GetIssuerSpecAndStatus(issuerInstance)
	if err != nil {
		r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonFailed, "Unable to get the Issuer Spec and Status. Ignoring", err)
		return ctrl.Result{}, nil
	}

	if !issuer.IsReady(issuerStatus) {
		return ctrl.Result{}, errIssuerNotReady
	}

	secret, err := common.GetSecret(r.Client, ctx, issuerInstance, issuerSpec.AuthSecretName, certificateRequest.Namespace, r.ClusterResourceNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, issuerSpec.AuthSecretName, err)
	}

	signer, err := r.SignerBuilder(issuerSpec, secret.Data, r.Client)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	leaf, ca, err := signer.Sign(ctx, logger, certificateRequest.Spec.Request)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}

	certificateRequest.Status.Certificate = leaf
	certificateRequest.Status.CA = ca
	r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonIssued, "Signed", nil)

	return ctrl.Result{}, nil
}

// ignore returns a boolean indicating whether reconciliation should be skipped.
func (r *CertificateRequestReconciler) ignore(logger logr.Logger, certificateRequest cmapi.CertificateRequest) bool {
	if !issuerRefMatchesGroup(certificateRequest) {
		logger.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return true
	}

	if IsAlreadyReady(certificateRequest) {
		logger.Info("CertificateRequest is Ready. Ignoring.")
		return true
	}

	if IsAlreadyFailed(certificateRequest) {
		logger.Info("CertificateRequest is Failed. Ignoring.")
		return true
	}

	if IsAlreadyDenied(certificateRequest) {
		logger.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return true
	}

	if r.CheckApprovedCondition {
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			logger.Info("CertificateRequest has not been approved yet. Ignoring.")
			return true
		}
	}

	return false
}

// report gives feedback by updating the Ready Condition of the Certificate Request.
// For added visibility it also logs a message and emits a Kubernetes Event.
func (r *CertificateRequestReconciler) report(logger logr.Logger, certificateRequest *cmapi.CertificateRequest, reason, message string, err error) {
	status := cmmeta.ConditionFalse
	if reason == cmapi.CertificateRequestReasonIssued {
		status = cmmeta.ConditionTrue
	}

	eventType := corev1.EventTypeNormal
	if err != nil {
		logger.Error(err, message)
		eventType = corev1.EventTypeWarning
		message = fmt.Sprintf("%s: %v", message, err)
	} else {
		logger.Info(message)
	}

	r.recorder.Event(certificateRequest, eventType, eventReasonCertificateRequestReconciler, message)
	cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady, status, reason, message)
}

// markAsDenied marks the certificateRequest as Denied by updating by setting
// Ready=Denied and setting FailureTime.
func (r *CertificateRequestReconciler) markAsDenied(logger logr.Logger, certificateRequest cmapi.CertificateRequest) {
	if certificateRequest.Status.FailureTime == nil {
		nowTime := metav1.NewTime(r.Clock.Now())
		certificateRequest.Status.FailureTime = &nowTime
	}

	message := "The CertificateRequest was denied by an approval controller"
	r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonDenied, message, nil)
}

// initializeReadyCondition returns true if it has added a Ready condition if such does not already exist,
// and false if the Ready condition already exists.
func (r *CertificateRequestReconciler) initializeReadyCondition(logger logr.Logger, certificateRequest *cmapi.CertificateRequest) bool {
	if ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		r.report(logger, certificateRequest, cmapi.CertificateRequestReasonPending, "Initialising Ready condition", nil)
		return true
	}

	return false
}

// getIssuer returns an Issuer or a ClusterIssuer.
func (r *CertificateRequestReconciler) getIssuer(logger logr.Logger, ctx context.Context, certificateRequest cmapi.CertificateRequest) (client.Object, error) {
	issuerGVK := certv1alpha1.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonFailed, "Unrecognised kind. Ignoring", fmt.Errorf("error interpreting issuerRef: %v", err))
		return nil, errUnrecognisedKind
	}

	issuerInstance := issuerRO.(client.Object)

	// create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}

	switch t := issuerInstance.(type) {
	case *certv1alpha1.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
		logger.Info("Kind is Issuer", "namespacedName", issuerName)
	case *certv1alpha1.ClusterIssuer:
		logger.Info("Type is ClusterIssuer", "certificateRequest.Namespace", issuerName)
	default:
		err = fmt.Errorf("unexpected issuer type: %v", t)
		r.report(logger, &certificateRequest, cmapi.CertificateRequestReasonFailed, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring", err)
		return issuerInstance, nil
	}

	if err := r.Get(ctx, issuerName, issuerInstance); err != nil {
		return issuerInstance, err
	}

	return issuerInstance, err
}

// issuerRefMatchesGroup returns a boolean indicating whether the issuerRef of the
// CertificateRequest matches the relevant API Group.
func issuerRefMatchesGroup(certificateRequest cmapi.CertificateRequest) bool {
	return certificateRequest.Spec.IssuerRef.Group == certv1alpha1.GroupVersion.Group
}
