package cert

// PostCertificateResponse represents the structure of the JSON response body for obtaining a certificate.
type PostCertificateResponse struct {
	Guid string `json:"taskId"`
}

// DownloadCertificateResponse represents the response received when downloading a certificate.
type DownloadCertificateResponse struct {
	Data string `json:"data"`
}
