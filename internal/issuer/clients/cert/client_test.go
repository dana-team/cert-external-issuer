package cert

import (
	"net/http"
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/test"
	httpClient "github.com/dana-team/cert-external-issuer/internal/issuer/clients/http"
	"github.com/google/go-cmp/cmp"
)

var (
	testAPIEndpoint      = "https://api.endpoint"
	testDownloadEndpoint = "https://download.endpoint"
	testToken            = "dummy-token"
	testForm             = "form"

	hClient        = http.Client{}
	testHTTPClient = httpClient.NewClient(hClient)
)

const (
	withAPIEndpoint      = "WithAPIEndpoint"
	withDownloadEndpoint = "WithDownloadEndpoint"
	withForm             = "WithForm"
	withToken            = "WithToken"
	withHTTPClient       = "WithHTTPClient"
)

func TestClientOptions(t *testing.T) {
	type args struct {
		name   string
		option func(*client)
	}
	type want struct {
		value interface{}
	}

	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldCreateSuccessfullyWithAPIEndpoint": {
			args: args{
				name:   withAPIEndpoint,
				option: WithAPIEndpoint(testAPIEndpoint),
			},
			want: want{
				value: testAPIEndpoint,
			},
		},
		"ShouldCreateSuccessfullyWithDownloadEndpoint": {
			args: args{
				name:   withDownloadEndpoint,
				option: WithDownloadEndpoint(testDownloadEndpoint),
			},
			want: want{
				value: testDownloadEndpoint,
			},
		},
		"ShouldCreateSuccessfullyWithToken": {
			args: args{
				name:   withToken,
				option: WithToken(testToken),
			},
			want: want{
				value: testToken,
			},
		},
		"ShouldCreateSuccessfullyWithHTTPClient": {
			args: args{
				name:   withHTTPClient,
				option: WithHTTPClient(http.Client{}),
			},
			want: want{
				value: testHTTPClient,
			},
		},
		"ShouldCreateSuccessfullyWithForm": {
			args: args{
				name:   withForm,
				option: WithForm(testForm),
			},
			want: want{
				value: testForm,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cl := NewClient(tc.args.option)
			switch tc.args.name {
			case withAPIEndpoint:
				if diff := cmp.Diff(tc.want.value, cl.(*client).apiEndpoint, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withDownloadEndpoint:
				if diff := cmp.Diff(tc.want.value, cl.(*client).downloadEndpoint, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withToken:
				if diff := cmp.Diff(tc.want.value, cl.(*client).token, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withHTTPClient:
				if diff := cmp.Diff(tc.want.value, cl.(*client).localHttpClient, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			}
		})
	}
}
