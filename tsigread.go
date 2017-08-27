// Utilities dealing with recovering TSIG keys from Bind-formatted key files
// in the filesystem.
package tlsa

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
)

// Read and parse a Bind-formatted key file for use with TSIG.
func ReadTSIG(fileName string) ([]dns.KEY, error) {

	ret := make([]dns.KEY, 0, 1)

	r, err := os.Open(fileName)
	if err != nil {
		return ret, fmt.Errorf("Failed to open TSIG file %s: %s\n",
			fileName, err)
	}

	p := dns.ParseZone(r, "", fileName)

	for t := range p {

		rr := t.RR

		if rr.Header().Class != dns.ClassINET {
			return ret, fmt.Errorf("Unexpected class %d in RR from TSIG key file %s: %s\n",
				rr.Header().Class, fileName, err)
		}

		if rr.Header().Rrtype != dns.TypeKEY {
			return ret, fmt.Errorf("Unexpected type %d in RR from TSIG key file %s: %s\n",
				rr.Header().Rrtype, fileName, err)
		}

		n := rr.(*dns.KEY)
		ret = append(ret, *n)
	}

	return ret, nil
}
