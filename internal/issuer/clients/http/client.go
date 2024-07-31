package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/dana-team/cert-external-issuer/internal/issuer/jsonutil"
	"github.com/go-logr/logr"

	"github.com/pkg/errors"
)

// Client is the interface to interact with HTTP
type Client interface {
	SendRequest(ctx context.Context, logger logr.Logger, method string, url string, body []byte, headers map[string][]string) (resp Response, err error)
}

type client struct {
	HTTPClient http.Client
}

// Response represents an HTTP response.
type Response struct {
	Body       string
	Headers    map[string][]string
	StatusCode int
}

// Request represents an HTTP request.
type Request struct {
	Method  string              `json:"method"`
	Body    string              `json:"body,omitempty"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// SendRequest sends an HTTP request and returns the response.
func (c *client) SendRequest(ctx context.Context, logger logr.Logger, method string, url string, body []byte, headers map[string][]string) (Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(body))

	if err != nil {
		return Response{}, err
	}

	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}

	response, err := c.HTTPClient.Do(request)
	logger.Info(fmt.Sprint("http request sent: ", jsonutil.ToJSON(Request{URL: url, Body: string(body), Method: method})))

	if err != nil {
		return Response{}, fmt.Errorf("http request to %q failed: %v", url, err)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return Response{}, fmt.Errorf("failed reading response body: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		logger.Info(fmt.Sprintf("request failed, method: %v, status code: %v, body: %v", method, response.StatusCode, responseBody))
		return Response{}, errors.New(http.StatusText(response.StatusCode))
	}

	beautifiedResponse := Response{
		Body:       string(responseBody),
		Headers:    response.Header,
		StatusCode: response.StatusCode,
	}

	err = response.Body.Close()
	if err != nil {
		return beautifiedResponse, err
	}

	return beautifiedResponse, nil
}

// NewClient returns a new HTTP Client.
func NewClient(hClient http.Client) Client {
	return &client{
		HTTPClient: hClient,
	}
}
