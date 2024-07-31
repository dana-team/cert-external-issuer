package validate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// validateKeyType validates that the key type specified in the CSR is allowed.
func validateKeyType(csr *x509.CertificateRequest, allowedPrivateKeyAlgorithms []string) error {
	publicKey := csr.PublicKey
	var keyType cmapi.PrivateKeyAlgorithm

	switch publicKey.(type) {
	case *rsa.PublicKey:
		keyType = cmapi.RSAKeyAlgorithm
	case *ecdsa.PublicKey:
		keyType = cmapi.ECDSAKeyAlgorithm
	case *ed25519.PublicKey:
		keyType = cmapi.Ed25519KeyAlgorithm
	default:
		return fmt.Errorf("unidentified key type")
	}

	if !containsString(string(keyType), allowedPrivateKeyAlgorithms) {
		return fmt.Errorf(errAllowedValuesStringMsg, ".spec.privateKey.algorithm", allowedPrivateKeyAlgorithms)
	}

	return nil
}

// validateKeySize validates that the key size specified in the CSR is allowed.
func validateKeySize(csr *x509.CertificateRequest, allowedPrivateKeySizes []int) error {
	publicKey := csr.PublicKey
	byteSize := 8

	publicKeySize := publicKey.(*rsa.PublicKey).Size() * byteSize
	if !containsInt(publicKeySize, allowedPrivateKeySizes) {
		return fmt.Errorf(errAllowedValuesIntMsg, ".spec.privateKey.size", allowedPrivateKeySizes)
	}

	return nil
}

// convertPrivateKeyAlgorithm converts a slice of PrivateKeyAlgorithm to a slice of strings.
func convertPrivateKeyAlgorithm(algorithms []cmapi.PrivateKeyAlgorithm) []string {
	converted := make([]string, 0, len(algorithms))

	for _, algorithm := range algorithms {
		converted = append(converted, string(algorithm))
	}

	return converted
}
