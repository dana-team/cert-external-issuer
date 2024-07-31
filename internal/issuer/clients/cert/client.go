package cert

import (
	"context"
	"net/http"

	httpClient "github.com/dana-team/cert-external-issuer/internal/issuer/clients/http"
	"github.com/dana-team/certificate-operator/api/v1alpha1"
	"github.com/go-logr/logr"
)

type ClientBuilder func(logr.Logger, *v1alpha1.CertificateConfig, map[string][]byte) (Client, error)

// Client is the interface to interact with Cert API service.
type Client interface {
	// PostCertificate sends a POST request to cert to create a new certificate and returns the GUID.
	PostCertificate(ctx context.Context, log logr.Logger, csrBytes []byte) (string, error)

	// DownloadCertificate downloads a certificate from the Cert API.
	DownloadCertificate(ctx context.Context, log logr.Logger, guid string) (DownloadCertificateResponse, error)
}

type client struct {
	localHttpClient  httpClient.Client
	apiEndpoint      string
	downloadEndpoint string
	form             string
	token            string
}

// NewClient returns a new client.
func NewClient(options ...func(*client)) Client {
	cl := &client{}
	for _, o := range options {
		o(cl)
	}

	return cl
}

// WithAPIEndpoint returns a client with the API Endpoint field populated.
func WithAPIEndpoint(apiEndpoint string) func(*client) {
	return func(c *client) {
		c.apiEndpoint = apiEndpoint
	}
}

// WithDownloadEndpoint returns a client with the Download Endpoint field populated.
func WithDownloadEndpoint(downloadEndpoint string) func(*client) {
	return func(c *client) {
		c.downloadEndpoint = downloadEndpoint
	}
}

// WithToken returns a client with the Token field populated.
func WithToken(token string) func(*client) {
	return func(c *client) {
		c.token = token
	}
}

// WithHTTPClient returns a client with the API Endpoint field populated.
func WithHTTPClient(hClient http.Client) func(*client) {
	return func(c *client) {
		c.localHttpClient = httpClient.NewClient(hClient)
	}
}

// WithForm returns a client with the Form field populated.
func WithForm(form string) func(*client) {
	return func(c *client) {
		c.form = form
	}
}
