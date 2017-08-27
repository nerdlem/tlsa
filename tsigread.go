// Utilities dealing with recovering TSIG keys from Bind-formatted key files
// in the filesystem.
package tlsa

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
)

// ReadTSIG Read and parse a Bind-formatted key file for use with TSIG.
func ReadTSIG(fileName string) ([]dns.KEY, error) {

	ret := make([]dns.KEY, 0, 1)

	r, err := os.Open(fileName)
	if err != nil {
		return ret, fmt.Errorf("failed to open TSIG file %s: %s",
			fileName, err)
	}

	p := dns.ParseZone(r, "", fileName)

	for t := range p {
		rr := t.RR
		if rr == nil {
			return ret, fmt.Errorf("TSIG file %s produced a nil RR", fileName)
		}

		if rr.Header().Class != dns.ClassINET {
			return ret, fmt.Errorf("unexpected class %d in RR from TSIG key file %s: %s",
				rr.Header().Class, fileName, err)
		}

		if rr.Header().Rrtype != dns.TypeKEY {
			return ret, fmt.Errorf("unexpected type %d in RR from TSIG key file %s: %s",
				rr.Header().Rrtype, fileName, err)
		}

		n := rr.(*dns.KEY)
		ret = append(ret, *n)
	}

	return ret, nil
}
