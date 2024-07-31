package cert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dana-team/cert-external-issuer/internal/issuer/jsonutil"
	"github.com/go-logr/logr"
)

const (
	authorizationToken      = "Bearer %v"
	authorizationHeaderKey  = "Authorization"
	acceptHeaderKey         = "accept"
	acceptHeaderValue       = "application/json"
	contentTypeHeaderKey    = "Content-Type"
	contentTypeTextPlainKey = "text/plain"
	csrKey                  = "csr"
)

var (
	errBodyIsNotJson         = errors.New("response body is not JSON")
	errFailedToUnmarshalBody = errors.New("failed to unmarshal response body")
	errPostToCertFailed      = errors.New("POST to cert failed")
	errDownloadToCertFailed  = errors.New("download request to Cert API failed")
)

// PostCertificate sends a POST request to the Cert API to create a new certificate and returns the GUID.
func (c *client) PostCertificate(ctx context.Context, logger logr.Logger, csrBytes []byte) (string, error) {
	url := fmt.Sprintf("%s%s", c.apiEndpoint, csrKey)

	response, err := c.localHttpClient.SendRequest(ctx, logger, http.MethodPost, url, csrBytes, c.constructHeaders())
	if err != nil {
		return "", fmt.Errorf("%w: %v", errPostToCertFailed, err)
	}

	var responseBody PostCertificateResponse
	if err = parseResponseBody(response.Body, &responseBody); err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToUnmarshalBody, err)
	}

	return responseBody.Guid, nil
}

// DownloadCertificate sends a GET request and downloads a certificate from the Cert API.
func (c *client) DownloadCertificate(ctx context.Context, logger logr.Logger, guid string) (DownloadCertificateResponse, error) {
	url := fmt.Sprintf("%s%s%s%s", c.apiEndpoint, guid, c.downloadEndpoint, c.form)

	response, err := c.localHttpClient.SendRequest(ctx, logger, http.MethodGet, url, []byte{}, c.constructHeaders())
	if err != nil {
		return DownloadCertificateResponse{}, fmt.Errorf("%w: %v", errDownloadToCertFailed, err)
	}

	var responseBody DownloadCertificateResponse
	if err = parseResponseBody(response.Body, &responseBody); err != nil {
		return DownloadCertificateResponse{}, fmt.Errorf("%w: %v", errFailedToUnmarshalBody, err)
	}

	return responseBody, nil
}

// parseResponseBody parses the response body received from the Cert API.
func parseResponseBody(body string, response interface{}) error {
	if !jsonutil.IsJSONString(body) {
		return errBodyIsNotJson
	}

	return json.Unmarshal([]byte(body), response)
}

// constructHeaders returns a map containing the needed headers for communicating with the Cert API.
func (c *client) constructHeaders() map[string][]string {
	return map[string][]string{
		authorizationHeaderKey: {fmt.Sprintf(authorizationToken, c.token)},
		acceptHeaderKey:        {acceptHeaderValue},
		contentTypeHeaderKey:   {contentTypeTextPlainKey},
	}
}
