package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/issuer/clients/cert"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	commonName         = "test.example.com"
	certificateRequest = "CERTIFICATE REQUEST"
	apiEndpoint        = "https://api.example.com"
	downloadEndpoint   = "https://download.example.com"
	formData           = "form-data"
	validIssueFactor   = "1.0"
	validIssueJitter   = "0.1"
	token              = "token"
	validToken         = "valid-token"
	validGuid          = "valid-guid"
	empty              = ""
	certificateConst   = "CERTIFICATE"
	organization       = "Company, INC."
	country            = "US"
	locality           = "San Francisco"
)

type mockKubeClient struct {
	kube.Client
}

type mockCertClient struct {
	mock.Mock
}

// generateCertificate generates a self-signed certificate and returns its PEM-encoded certificate and private key.
func generateCertificate() (certPEM []byte, err error) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
			Locality:     []string{locality},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certBuffer := new(bytes.Buffer)
	if err = pem.Encode(certBuffer, &pem.Block{
		Type:  certificateConst,
		Bytes: certBytes,
	}); err != nil {
		return nil, err
	}

	return certBuffer.Bytes(), nil
}

func (m *mockCertClient) PostCertificate(ctx context.Context, log logr.Logger, csrBytes []byte) (string, error) {
	args := m.Called(ctx, log, csrBytes)
	return args.String(0), args.Error(1)
}

func (m *mockCertClient) DownloadCertificate(ctx context.Context, log logr.Logger, guid string) (cert.DownloadCertificateResponse, error) {
	args := m.Called(ctx, log, guid)
	return args.Get(0).(cert.DownloadCertificateResponse), args.Error(1)
}

func generateMockCSR() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  certificateRequest,
		Bytes: csrBytes,
	})

	return csrPEM, nil
}

func TestCertSignerFromIssuerAndSecretData(t *testing.T) {
	type params struct {
		issuerSpec *v1alpha1.IssuerSpec
		secretData map[string][]byte
		kubeClient kube.Client
	}

	type want struct {
		err error
	}
	validIssuerSpec := &v1alpha1.IssuerSpec{
		APIEndpoint:      apiEndpoint,
		DownloadEndpoint: downloadEndpoint,
		Form:             formData,
		HTTPConfig: v1alpha1.HTTPConfig{
			RetryBackoff: v1alpha1.RetryBackoff{
				Duration: metav1.Duration{Duration: 5 * time.Second},
				Factor:   validIssueFactor,
				Jitter:   validIssueJitter,
				Steps:    10,
			},
		},
	}

	validSecretData := map[string][]byte{
		token: []byte(validToken),
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidData": {
			params: params{
				issuerSpec: validIssuerSpec,
				secretData: validSecretData,
				kubeClient: &mockKubeClient{},
			},
			want: want{
				err: nil,
			},
		},
		"ShouldFailWithMissingToken": {
			params: params{
				issuerSpec: validIssuerSpec,
				secretData: map[string][]byte{},
				kubeClient: &mockKubeClient{},
			},
			want: want{
				err: errMissingTokenData,
			},
		},
		"ShouldFailWithMissingAPIEndpoint": {
			params: params{
				issuerSpec: &v1alpha1.IssuerSpec{
					DownloadEndpoint: downloadEndpoint,
					Form:             formData,
				},
				secretData: validSecretData,
				kubeClient: &mockKubeClient{},
			},
			want: want{
				err: errMissingAPIEndpoint,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CertSignerFromIssuerAndSecretData(test.params.issuerSpec, test.params.secretData, test.params.kubeClient)
			if test.want.err != nil {
				assert.ErrorIs(t, err, test.want.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildHTTPClient(t *testing.T) {
	type params struct {
		issuerSpec *v1alpha1.IssuerSpec
	}

	type want struct {
		timeout       time.Duration
		skipVerifyTLS bool
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldUseDefaultTimeout": {
			params: params{
				issuerSpec: &v1alpha1.IssuerSpec{},
			},
			want: want{
				timeout:       defaultWaitTimeout,
				skipVerifyTLS: false,
			},
		},
		"ShouldUseCustomTimeout": {
			params: params{
				issuerSpec: &v1alpha1.IssuerSpec{
					HTTPConfig: v1alpha1.HTTPConfig{
						WaitTimeout: &metav1.Duration{Duration: 10 * time.Minute},
					},
				},
			},
			want: want{
				timeout:       10 * time.Minute,
				skipVerifyTLS: false,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			client := buildHTTPClient(test.params.issuerSpec)
			assert.Equal(t, test.want.timeout, client.Timeout)
			transport := client.Transport.(*http.Transport)
			assert.Equal(t, test.want.skipVerifyTLS, transport.TLSClientConfig.InsecureSkipVerify)
		})
	}
}

func TestSignCSR(t *testing.T) {
	type params struct {
		postResponse     string
		postError        error
		downloadResponse cert.DownloadCertificateResponse
		downloadError    error
		retryAttempts    int
	}

	type want struct {
		err     error
		hasCert bool
	}

	certificate, err := generateCertificate()
	assert.NoError(t, err)

	encodedCert := base64.StdEncoding.EncodeToString(certificate)

	mockCSR, err := generateMockCSR()
	assert.NoError(t, err)

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidResponse": {
			params: params{
				postResponse: validGuid,
				postError:    nil,
				downloadResponse: cert.DownloadCertificateResponse{
					Data: encodedCert,
				},
				downloadError: nil,
				retryAttempts: 1,
			},
			want: want{
				err:     nil,
				hasCert: true,
			},
		},
		"ShouldFailWithPostError": {
			params: params{
				postResponse:     empty,
				postError:        fmt.Errorf("post error"),
				downloadResponse: cert.DownloadCertificateResponse{},
				downloadError:    nil,
				retryAttempts:    1,
			},
			want: want{
				err:     errFailedSigningCertificate,
				hasCert: false,
			},
		},
		"ShouldFailWithDownloadError": {
			params: params{
				postResponse:     validGuid,
				postError:        nil,
				downloadResponse: cert.DownloadCertificateResponse{},
				downloadError:    fmt.Errorf("download error"),
				retryAttempts:    1,
			},
			want: want{
				err:     errFailedSigningCertificate,
				hasCert: false,
			},
		},
		"ShouldRetryOnNotFound": {
			params: params{
				postResponse: validGuid,
				postError:    nil,
				downloadResponse: cert.DownloadCertificateResponse{
					Data: encodedCert,
				},
				downloadError: errors.New(http.StatusText(http.StatusNotFound)),
				retryAttempts: 2,
			},
			want: want{
				err:     nil,
				hasCert: true,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			mockClient := new(mockCertClient)
			signer := &certSigner{
				certClient: mockClient,
				waitBackoff: wait.Backoff{
					Duration: time.Millisecond,
					Factor:   1.0,
					Jitter:   0.1,
					Steps:    test.params.retryAttempts,
				},
			}

			mockClient.On("PostCertificate", mock.Anything, mock.Anything, mock.Anything).
				Return(test.params.postResponse, test.params.postError)

			if test.params.postError == nil {
				if strings.Contains(name, "ShouldRetryOnNotFound") {
					mockClient.On("DownloadCertificate", mock.Anything, mock.Anything, mock.Anything).
						Return(cert.DownloadCertificateResponse{}, test.params.downloadError).Once()
					mockClient.On("DownloadCertificate", mock.Anything, mock.Anything, mock.Anything).
						Return(test.params.downloadResponse, nil).Once()
				} else {
					mockClient.On("DownloadCertificate", mock.Anything, mock.Anything, mock.Anything).
						Return(test.params.downloadResponse, test.params.downloadError)
				}
			}

			chainPEM, caPEM, err := signer.signCSR(context.Background(), logr.Discard(), mockClient, mockCSR)

			if test.want.err != nil {
				assert.ErrorIs(t, err, test.want.err)
				assert.Empty(t, chainPEM)
				assert.Empty(t, caPEM)
			} else {
				assert.NoError(t, err)
				if test.want.hasCert {
					assert.NotEmpty(t, chainPEM)
				} else {
					assert.Empty(t, chainPEM)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}
