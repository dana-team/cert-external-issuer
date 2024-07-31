package validate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
)

func TestValidateKeyType(t *testing.T) {
	type params struct {
		algorithm                   cmapi.PrivateKeyAlgorithm
		allowedPrivateKeyAlgorithms []string
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidRSAKeyType": {
			params: params{
				algorithm:                   cmapi.RSAKeyAlgorithm,
				allowedPrivateKeyAlgorithms: []string{"RSA"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldSucceedWithValidECDSAKeyType": {
			params: params{
				algorithm:                   cmapi.ECDSAKeyAlgorithm,
				allowedPrivateKeyAlgorithms: []string{"ECDSA"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldSucceedWithValidEd25519KeyType": {
			params: params{
				algorithm:                   cmapi.Ed25519KeyAlgorithm,
				allowedPrivateKeyAlgorithms: []string{"Ed25519"},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidKeyType": {
			params: params{
				algorithm:                   cmapi.RSAKeyAlgorithm,
				allowedPrivateKeyAlgorithms: []string{"ECDSA", "Ed25519"},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesStringMsg, ".spec.privateKey.algorithm", []string{"ECDSA", "Ed25519"}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := generateMockCSR(test.params.algorithm, 4096)
			assert.NoError(t, err)

			err = validateKeyType(csr, test.params.allowedPrivateKeyAlgorithms)
			if test.want.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.want.errMsg)
			}
		})
	}
}

func TestValidateKeySize(t *testing.T) {
	type params struct {
		algorithm              cmapi.PrivateKeyAlgorithm
		keySize                int
		allowedPrivateKeySizes []int
	}

	type want struct {
		errMsg string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithValidRSAKeySize": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                4096,
				allowedPrivateKeySizes: []int{2048, 4096},
			},
			want: want{
				errMsg: "",
			},
		},
		"ShouldFailWithInvalidKeySize": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                2048,
				allowedPrivateKeySizes: []int{1024, 4096},
			},
			want: want{
				errMsg: fmt.Sprintf(errAllowedValuesIntMsg, ".spec.privateKey.size", []int{1024, 4096}),
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := generateMockCSR(test.params.algorithm, test.params.keySize)
			assert.NoError(t, err)

			err = validateKeySize(csr, test.params.allowedPrivateKeySizes)
			if test.want.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.want.errMsg)
			}
		})
	}
}

// generateMockCSR is a helper to generate mock CSR with a specific key type.
func generateMockCSR(keyType cmapi.PrivateKeyAlgorithm, keySize int) (*x509.CertificateRequest, error) {
	var pubKey interface{}
	switch keyType {
	case cmapi.RSAKeyAlgorithm:
		privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, err
		}
		pubKey = &privateKey.PublicKey
	case cmapi.ECDSAKeyAlgorithm:
		// ECDSA key size is determined by the curve, so we'll use P256 (256 bits)
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubKey = &privateKey.PublicKey
	case cmapi.Ed25519KeyAlgorithm:
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		pubKey = &publicKey
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	template := &x509.CertificateRequest{
		PublicKey: pubKey,
	}

	return template, nil
}
