// Utility functions dealing with X509 certificate handling / conversion /
// data extraction.
package tlsa

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func GetCertificate(certificateFile string) (*x509.Certificate, error) {
	certificateBytes, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read certificate file %s: %s\n",
			certificateFile, err)
	}

	block, _ := pem.Decode(certificateBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse PEM block")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %s\n", err)
	}

	return certificate, nil
}

// Return the list of domain names in the CN or alternative sections of this
// certificate

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
