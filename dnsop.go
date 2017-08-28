package tlsa

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

// UDPBUFSIZE contains the UDP packet size advertised with EDNS(0). Defaults
// to 4096.
var UDPBUFSIZE = uint16(4096)

// TSIGFUDGE containts the fudge interval for TSIG signatures
var TSIGFUDGE = uint16(300)

// Usage contains the TLSA Usage parameter, to be set. This value is of type
// uint
var Usage = uint(1)

// Selector containts the TLSA Selector parameter, to be set. This value is of
// type uint
var Selector = uint(2)

// MatchingType contains TLSA MatchingType parameter, to be set. This value is
// of type uint
var MatchingType = uint(3)

// NameServer is the Global Name Server to use for sending the updates.
var NameServer = "127.0.0.1:53"

// TsigAndSend signs a composed DNS message (dns.Msg) and sends it using the
// global name server configured via NameServer.
func TsigAndSend(m *dns.Msg, keys []dns.KEY) error {

	if m.Id == 0 {
		m.Id = dns.Id()
	}

	for _, t := range keys {

		algo := dns.HmacMD5

		// This map of algorithms was taken from Perl's Net::DNS::RR::TSIG
		// -- notice that a couple hash algorithms are not supported in
		// the Go library. Let's hope these are seldom used.

		switch t.Algorithm {
		case 157:
			algo = dns.HmacMD5
		case 161:
			algo = dns.HmacSHA1
		// case 162:
		// 	algo = dns.HmacSHA224
		case 163:
			algo = dns.HmacSHA256
		// case 164:
		// 	algo = dns.HmacSHA384
		case 165:
			algo = dns.HmacSHA512
		default:
			return fmt.Errorf("unknown HMAC algorithm %d in TSIG key %s",
				t.Algorithm, t.Hdr.Name)
		}

		m.SetTsig(t.Hdr.Name, algo, TSIGFUDGE, time.Now().Unix())

		c := new(dns.Client)
		c.TsigSecret = map[string]string{t.Hdr.Name: t.PublicKey}

		in, _, err := c.Exchange(m, NameServer)
		if err != nil {
			return fmt.Errorf("error processing records via %s: %s",
				NameServer, err)
		}

		if in.Opcode != dns.OpcodeUpdate || in.Rcode != dns.RcodeSuccess {
			return fmt.Errorf(
				"update response was unsuccessful (opcode=%d, rcode=%d)",
				in.Opcode, in.Rcode)
		}
	}
	return nil
}

// GetZone finds the apex where the updated name is located at. A SOA DNS
// query is sent to the global Name Server -- expected to be the (possibly
// hidden) master server managing this zone's data.
func GetZone(name string, ns string) (string, error) {

	// Perform an initial query to assert the SOA corresponding to the name

	c := new(dns.Client)

	for attempt := 0; attempt < 5; attempt++ {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
		m.SetEdns0(UDPBUFSIZE, true)

		in, rtt, err := c.Exchange(m, NameServer)
		if err != nil {
			fmt.Printf("error processing records via %s (rtt %d): %s\n",
				NameServer, rtt, err)
			continue
		}

		// Identify the SOA RR and respond with its name

		for _, rr := range in.Ns {
			h := rr.Header()
			if h.Class == dns.ClassINET && h.Rrtype == dns.TypeSOA {
				return h.Name, nil
			}
		}

		for _, rr := range in.Answer {
			h := rr.Header()
			if h.Class == dns.ClassINET && h.Rrtype == dns.TypeSOA {
				return h.Name, nil
			}
		}

		panic(fmt.Sprintf(
			"SOA response for %s had no usable authority records",
			name))
	}

	return ".", fmt.Errorf(
		"too many unsuccessful attempts to get SOA for %s",
		name)
}

// DeleteRRs composes a DNS Dynamic Update to delete all TLSA RRs. This can be
// used to wipe clean the namespace. Uses the TsigAndSend() helper to cause
// the update to be sent to the global Name Server for processing.
func DeleteRRs(pinNames []string, keys []dns.KEY) {
	for _, domain := range pinNames {

		zone, err := GetZone(domain, NameServer)
		if err != nil {
			panic(err)
		}

		m := new(dns.Msg)
		m.SetUpdate(zone)

		records := make([]dns.RR, 0, 1)

		rTLSA := new(dns.TLSA)
		rTLSA.Hdr = dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeTLSA,
			Class:  dns.ClassINET,
		}

		records = append(records, rTLSA)

		m.RemoveRRset(records)

		err = TsigAndSend(m, keys)
		if err != nil {
			panic(err)
		}
	}
}

// AddRR composes a DNS Dynamic Updte to add one or more TLSA RR. The process
// is meant to be additive, so that multiple records can be appended. The
// update request is sent via the TsigAndSend() helper.
func AddRR(pinNames []string, keys []dns.KEY, crtSigns []string) {
	for _, domain := range pinNames {
		zone, err := GetZone(domain, NameServer)
		if err != nil {
			panic(err)
		}

		records := make([]dns.RR, 0, 1)

		for _, sign := range crtSigns {

			rTLSA := new(dns.TLSA)
			rTLSA.Hdr.Name = dns.Fqdn(domain)
			rTLSA.Hdr.Rrtype = dns.TypeTLSA
			rTLSA.Usage = uint8(Usage)
			rTLSA.Selector = uint8(Selector)
			rTLSA.MatchingType = uint8(MatchingType)
			rTLSA.Certificate = sign

			records = append(records, rTLSA)
		}

		m := new(dns.Msg)
		m.SetUpdate(zone)
		m.Insert(records)

		err = TsigAndSend(m, keys)
		if err != nil {
			panic(err)
		}
	}
}

// CertificateSignatures precalculates the certificate signatures from the
// pinned certificates to use. These are suitable for setting up TLSA records
// without reading certs multiple times, as would be required by the
// underlying functions in the dns library.
func CertificateSignatures(certFiles []string) ([]string, error) {
	sigs := make([]string, 0, 1)

	for _, crtName := range certFiles {
		c, err := GetCertificate(crtName)
		if err != nil {
			panic(err)
		}

		h, err := dns.CertificateToDANE(
			uint8(Selector),
			uint8(MatchingType), c)
		if err != nil {
			panic(err)
		}

		sigs = append(sigs, h)
	}

	return sigs, nil
}
