package certhandler

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	errCannotDecodeData    = "cannot decode PKCS#12 data: %v"
	errCannotDecodeB64Data = "cannot decode base64-encoded PKCS#12 data: %v"
)

// Decoder decodes the PKCS#12 formatted TLS data.
func Decoder(data, password string) ([]byte, []byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf(errCannotDecodeB64Data, err)
	}

	_, certificate, caCert, err := pkcs12.DecodeChain(decodedData, password)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf(errCannotDecodeData, err)
	}

	certs := caCert
	certs = append(certs, certificate)

	return compileCertificatesToPEMBytes(certs)
}

// compileCertificatesToPEMBytes takes a slice of x509 certificates and returns a string containing the certificates in PEM format
// If an error occurred, the function logs the error and continues to parse the remaining objects.
func compileCertificatesToPEMBytes(certificates []*x509.Certificate) ([]byte, []byte, error) {
	bundlePEM, err := cmpki.ParseSingleCertificateChain(certificates)
	if err != nil {
		return make([]byte, 0), make([]byte, 0), err
	}

	return bundlePEM.ChainPEM, bundlePEM.CAPEM, nil
}
