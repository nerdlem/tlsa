// Automatically update DANE records matching domain names present in X509
// certificates

package main

import (
	"flag"
	"fmt"
	"github.com/nerdlem/tlsa"
	"os"
	"strings"
)

var certPinFiles, namesList, tsigKeyFile, tsigKeyName string
var clearAll, dryRun bool
var pinCerts, pinNames, certNames []string

// Initialize command line flags ahead of time.
func init() {
	flag.StringVar(&certPinFiles, "pin-certs", "",
		"X.509 certificates file to pin via TLSA (comma separated)")
	flag.StringVar(&tsigKeyFile, "tsig-file", "tsig.key",
		"TSIG key file")
	flag.BoolVar(&clearAll, "clear-all", false,
		"Clear all existing TLSA records")
	flag.BoolVar(&dryRun, "dry-run", false,
		"Output information about what would be done but make no changes")
	flag.StringVar(&tlsa.NameServer, "ns", "127.0.0.1:53",
		"Authoritative name server to send updates to")
	flag.StringVar(&namesList, "names", "",
		"Names to pin the certificate to")
	flag.UintVar(&tlsa.Selector, "tlsa-selector", 1,
		"TLSA selector code (see RFC-6698§2.1.2")
	flag.UintVar(&tlsa.MatchingType, "tlsa-match", 2,
		"TLSA Matching Type code (see RFC-6698§2.1.3")
	flag.UintVar(&tlsa.Usage, "tlsa-usage", 3,
		"TLSA Usage code (see RFC-6698§2.1.1")
}

func main() {
	flag.Parse()

	// Read the TSIG key file to prepare the dynamic updates

	m, err := tlsa.ReadTSIG(tsigKeyFile)
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

	if dryRun {
		for _, k := range m {
			fmt.Printf("dry-run: Will use TSIG key %s\n", k.PublicKey)
		}
	}

	if clearAll {
		if dryRun {
			for _, n := range pinNames {
				fmt.Printf("dry-run: Clear all TLSA RRs for %s\n", n)
			}
		} else {
			tlsa.DeleteRRs(pinNames, m)
		}
	}

	if len(crtSigns) != 0 {
		if dryRun {
			for _, n := range pinNames {
				for _, s := range crtSigns {
					fmt.Printf("dry-run: Add TLSA RRs for %s: %s\n",
						n, s)
				}
			}
		} else {
			tlsa.AddRR(pinNames, m, crtSigns)
		}
	}

	os.Exit(0)
}
