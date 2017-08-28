package tlsa

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// GetCertificate reads a PEM encoded certificate file or public key.
//
// When fed a PEM encoded certificate, the x509.Certificate object is
// returned. If fed a public key in PEM format, a pseudo x509.Certificate is
// returned, with only the public key field populated. This is enough to
// calculate the TLSA signature.
//
// Suitable errors are returned when conditions aren't favorable.
func GetCertificate(certificateFile string) (*x509.Certificate, error) {
	certificateBytes, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %s",
			certificateFile, err)
	}

	block, _ := pem.Decode(certificateBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block on file %s",
			certificateFile)
	}

	var certificate *x509.Certificate

	switch block.Type {
	case "CERTIFICATE":
		certificate, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %s: %s",
				certificateFile, err)
		}

	case "PUBLIC KEY":
		certificate = &x509.Certificate{
			Raw: nil,
			RawSubjectPublicKeyInfo: block.Bytes,
		}
	default:
		return nil, fmt.Errorf("cert file %s is of unsupported type %s",
			certificateFile, block.Type)
	}
	return certificate, nil
}

// GetDomainNamesFromCertFile returns the list of domain names in the CN or
// alternative sections of this certificate
func GetDomainNamesFromCertFile(certificateFile string) ([]string, error) {
	domains := make(map[string]bool)

	certificate, err := GetCertificate(certificateFile)
	if err != nil {
		return nil, err
	}

	// Navigate the certificate to find the domain names for which we'll later
	// produce updates. Start with CN in the Subject of the certificate.

	dom := certificate.Subject.CommonName
	if dom != "" {
		domains[dom] = true
	}

	// Extract the extra DNS names

	for _, dom := range certificate.DNSNames {
		domains[dom] = true
	}

	ret := make([]string, 0, len(domains))

	for domain := range domains {
		ret = append(ret, domain)
	}

	return ret, nil
}
