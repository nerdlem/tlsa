// Automatically update DANE records matching domain names present in X509
// certificates

package main

import (
	"flag"
	"fmt"
	"strings"
	"tlsa"
)

var certPinFiles, namesList, nameServer, tsigKeyFile, tsigKeyName string
var tlsaUsage, tlsaSelector, tlsaMatchingType uint
var clearAll bool
var pinCerts, pinNames, certNames []string

// Initialize command line flags ahead of time.
func init() {
	flag.StringVar(&certPinFiles, "pin-certs", "",
		"X509 certificates file to pin via TLSA (comma separated)")
	flag.StringVar(&tsigKeyFile, "tsig-file", "tsig.key",
		"TSIG key file")
	flag.BoolVar(&clearAll, "clear-all", false,
		"Clear all existing TLSA records")
	flag.StringVar(&nameServer, "ns", "127.0.0.1:53",
		"Authoritative nameserver to send updates to")
	flag.StringVar(&namesList, "names", "",
		"Names to pin the certificate to")
	flag.UintVar(&tlsaSelector, "tlsa-selector", 1,
		"TLSA selector code (see RFC-6698§2.1.2 (default 1)")
	flag.UintVar(&tlsaMatchingType, "tlsa-match", 2,
		"TLSA Matching Type code (see RFC-6698§2.1.3 (default 2)")
	flag.UintVar(&tlsaUsage, "tlsa-usage", 3,
		"TLSA Usage code (see RFC-6698§2.1.1 (default 3)")
}

func main() {
	flag.Parse()

	// Read the TSIG key file to prepare the dynamic updates

	m, err := tlsa.readTSIG(tsigKeyFile)
	if err != nil {
		panic(fmt.Sprintf("Error processing TSIG key file: %s", err))
	}

	// Compose the domain lists we'll be working with based on the
	// certificates and the command line options.

	pinNames = make([]string, 0, 1)
	pinCerts = make([]string, 0, 1)

	if namesList != "" {
		pinNames = append(pinNames, strings.Split(namesList, ",")...)
	}

	if certPinFiles != "" {
		pinCerts = append(pinCerts, strings.Split(certPinFiles, ",")...)
	}

	if len(pinNames) == 0 {
		panic("No pinned-names to work with. Use --names")
	}

	var crtSigns []string

	if len(pinCerts) != 0 {
		crtSigns, err = tlsa.CertificateSignatures(pinCerts)
		if err != nil {
			panic(err)
		}
	}

	if clearAll {
		tlsa.DeleteRRs(pinNames, m)
	}

	if len(crtSigns) != 0 {
		tlsa.AddRR(pinNames, m, crtSigns)
	}
}
