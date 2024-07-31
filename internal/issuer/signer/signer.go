package signer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dana-team/cert-external-issuer/internal/issuer/validate"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	cmpkgutil "github.com/cert-manager/cert-manager/pkg/util/pki"
	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/issuer/clients/cert"
	"github.com/go-logr/logr"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultWaitTimeout           = 5 * time.Minute
	defaultRetryDuration         = 5 * time.Second
	defaultRetrySteps            = 10
	defaultRetryFactor           = 1.0
	defaultRetryJitter           = 0.1
	authorizationHeaderSecretKey = "token"
	certificateRequestBlockType  = "CERTIFICATE REQUEST"
)

var (
	errMissingTokenData           = errors.New("missing token data in secret")
	errMissingAPIEndpoint         = errors.New("missing api endpoint")
	errMissingDownloadEndpoint    = errors.New("missing download endpoint")
	errMissingKubeClient          = errors.New("missing kube client")
	errMissingForm                = errors.New("missing form")
	errFailedBuildingRetryBackoff = errors.New("failed to build retry backoff")
	errFailedSigningCertificate   = errors.New("failed to sign certificate")
	errFailedValidatingCSR        = errors.New("failed to validate CSR")
	errFailedParsingCSR           = errors.New("failed to parse CSR, PEM block type must be CERTIFICATE REQUEST, actual")
	errFailedDecodingData         = errors.New("failed to decode Certificate data")
	errFailedParsingCertificate   = errors.New("failed to parse Certificate")
)

type certSigner struct {
	certClient   cert.Client
	waitBackoff  wait.Backoff
	restrictions certv1alpha1.Restrictions
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*certv1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(ctx context.Context, logger logr.Logger, csrBytes []byte) ([]byte, []byte, error)
}

type SignerBuilder func(*certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (Signer, error)

func CertSignerHealthCheckerFromIssuerAndSecretData(*certv1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error) {
	return &certSigner{}, nil
}

// CertSignerFromIssuerAndSecretData is a wrapper for certSignerFromIssuerAndSecretData that returns a Signer interface.
func CertSignerFromIssuerAndSecretData(issuerSpec *certv1alpha1.IssuerSpec, secretData map[string][]byte, kubeClient kube.Client) (Signer, error) {
	return certSignerFromIssuerAndSecretData(issuerSpec, secretData, kubeClient)
}

// certSignerFromIssuerAndSecretData creates a new Signer instance using the provided issuer spec and secret data.
func certSignerFromIssuerAndSecretData(issuerSpec *certv1alpha1.IssuerSpec, secretData map[string][]byte, kubeClient kube.Client) (Signer, error) {
	tokenData := string(secretData[authorizationHeaderSecretKey])
	if tokenData == "" {
		return nil, errMissingTokenData
	}

	apiEndpoint := issuerSpec.APIEndpoint
	if apiEndpoint == "" {
		return nil, errMissingAPIEndpoint
	}

	downloadEndpoint := issuerSpec.DownloadEndpoint
	if downloadEndpoint == "" {
		return nil, errMissingDownloadEndpoint
	}

	form := issuerSpec.Form
	if form == "" {
		return nil, errMissingForm
	}

	if kubeClient == nil {
		return nil, errMissingKubeClient
	}

	backoff, err := buildRetryBackoff(issuerSpec)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errFailedBuildingRetryBackoff, err)
	}

	restrictions := issuerSpec.CertificateRestrictions

	return &certSigner{
		certClient: cert.NewClient(
			cert.WithToken(tokenData),
			cert.WithAPIEndpoint(apiEndpoint),
			cert.WithDownloadEndpoint(downloadEndpoint),
			cert.WithForm(form),
			cert.WithHTTPClient(buildHTTPClient(issuerSpec)),
		),
		restrictions: restrictions,
		waitBackoff:  backoff,
	}, nil

}

// buildHTTPClient returns a http.Client object using values from the issuerSpec.
func buildHTTPClient(issuerSpec *certv1alpha1.IssuerSpec) http.Client {
	waitTimeout := issuerSpec.HTTPConfig.WaitTimeout
	timeout := defaultWaitTimeout
	if waitTimeout != nil {
		timeout = waitTimeout.Duration
	}

	skipVerifyTLS := issuerSpec.HTTPConfig.SkipVerifyTLS

	return http.Client{
		Transport: &http.Transport{
			// #nosec G402
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerifyTLS},
		},
		Timeout: timeout,
	}
}

// buildRetryBackoff returns a wait.Backoff object using values from the issuerSpec.
func buildRetryBackoff(issuerSpec *certv1alpha1.IssuerSpec) (wait.Backoff, error) {
	var backoff wait.Backoff
	var retryBackoffFactor, retryBackoffJitter float64
	var err error

	steps := defaultRetrySteps
	retryBackoffSteps := issuerSpec.HTTPConfig.RetryBackoff.Steps
	if retryBackoffSteps != 0 {
		steps = retryBackoffSteps
	}

	duration := defaultRetryDuration
	retryBackoffDuration := issuerSpec.HTTPConfig.RetryBackoff.Duration
	if retryBackoffDuration.Duration != 0 {
		duration = retryBackoffDuration.Duration
	}

	factor := defaultRetryFactor
	if issuerSpec.HTTPConfig.RetryBackoff.Factor != "" {
		retryBackoffFactor, err = strconv.ParseFloat(issuerSpec.HTTPConfig.RetryBackoff.Factor, 64)
		if err != nil {
			return backoff, err
		}

		if retryBackoffFactor != 0 {
			factor = retryBackoffFactor
		}
	}

	jitter := defaultRetryJitter
	if issuerSpec.HTTPConfig.RetryBackoff.Jitter != "" {
		retryBackoffJitter, err = strconv.ParseFloat(issuerSpec.HTTPConfig.RetryBackoff.Jitter, 64)
		if err != nil {
			return backoff, err
		}

		if retryBackoffJitter != 0 {
			jitter = retryBackoffJitter
		}
	}

	backoff = wait.Backoff{
		Duration: duration,
		Steps:    steps,
		Factor:   factor,
		Jitter:   jitter,
	}

	return backoff, nil
}

func (cs *certSigner) Check() error {
	return nil
}

func (cs *certSigner) Sign(ctx context.Context, logger logr.Logger, csrBytes []byte) ([]byte, []byte, error) {
	csr, err := parseCSR(csrBytes)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	if err := validate.EnsureCSR(csr, cs.restrictions); err != nil {
		return []byte{}, []byte{}, fmt.Errorf("%w: %v", errFailedValidatingCSR, err)
	}

	return cs.signCSR(ctx, logger, cs.certClient, csrBytes)
}

// parseCSR extracts PEM from request object.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != certificateRequestBlockType {
		return nil, fmt.Errorf("%w: %q", errFailedParsingCSR, block)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// signCSR interacts with the Cert API and returns a signed CSR.
func (cs *certSigner) signCSR(ctx context.Context, logger logr.Logger, certClient cert.Client, csrBytes []byte) ([]byte, []byte, error) {
	var err error
	var guid string
	var response cert.DownloadCertificateResponse

	guid, err = certClient.PostCertificate(ctx, logger, csrBytes)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("%w: %v", errFailedSigningCertificate, err)
	}

	err = retry.OnError(cs.waitBackoff, isErrorNotFound, func() error {
		response, err = certClient.DownloadCertificate(ctx, logger, guid)
		return err
	})
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("%w: %v", errFailedSigningCertificate, err)
	}

	decodedData, err := base64.StdEncoding.DecodeString(response.Data)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("%w: %v", errFailedDecodingData, err)
	}

	bundle, err := cmpkgutil.ParseSingleCertificateChainPEM(decodedData)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("%w: %v", errFailedParsingCertificate, err)
	}

	return bundle.ChainPEM, bundle.CAPEM, nil
}

// IsErrorNotFound returns a boolean indicating whether an error includes a Not Found error.
func isErrorNotFound(err error) bool {
	return strings.Contains(err.Error(), http.StatusText(http.StatusNotFound))
}
