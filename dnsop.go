// This package provides functions to help with managing TLSA records via DNS
// Dynamic Updates.
package tlsa

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

// UDP packet size advertised with EDNS(0)
var UDPBUFSIZE = uint16(4096)

// Fudge interval for TSIG signatures
var TSIGFUDGE = uint16(300)

// TLSA Usage parameter, to be set.
var Usage = uint(1)

// TLSA Selector parameter, to be set.
var Selector = uint(2)

// TLSA MatchingType parameter, to be set.
var MatchingType = uint(3)

// Global nameserver to use for sending the updates.
var nameServer = "127.0.0.1:53"

// Given a composed DNS message object (dns.Msg), sign it using TSIG and send
// to the global name server.
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
			return fmt.Errorf("Unknown HMAC algorithm %d in TSIG key %s",
				t.Algorithm, t.Hdr.Name)
		}

		m.SetTsig(t.Hdr.Name, algo, TSIGFUDGE, time.Now().Unix())

		c := new(dns.Client)
		c.TsigSecret = map[string]string{t.Hdr.Name: t.PublicKey}

		in, _, err := c.Exchange(m, nameServer)
		if err != nil {
			return fmt.Errorf("Error processing records via %s: %s\n",
				nameServer, err)
		}

		if in.Opcode != dns.OpcodeUpdate || in.Rcode != dns.RcodeSuccess {
			return fmt.Errorf(
				"Update response was unsuccessful (opcode=%d, rcode=%d)\n",
				in.Opcode, in.Rcode)
		}
	}
	return nil
}

// Find the apex where the updated name is located at. The DNS query is sent
// to the global nameServer -- expected to be the (possibly hidden) master
// server.
func GetZone(name string, ns string) (string, error) {

	// Perform an initial query to assert the SOA corresponding to the name

	c := new(dns.Client)

	for attempt := 0; attempt < 5; attempt++ {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
		m.SetEdns0(UDPBUFSIZE, true)

		in, rtt, err := c.Exchange(m, nameServer)
		if err != nil {
			fmt.Printf("Error processing records via %s (rtt %d): %s\n",
				nameServer, rtt, err)
			continue
		}

		// Identify the SOA RR and respond with its name

		for _, rr := range in.Ns {
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
		"Too many unsuccessful attempts to get SOA for %s",
		name)
}

// Compose a DNS Dynamic Update to delete all TLSA RRs. This can be used to
// wipe clean the namespace. Use TsigAndSend() to cause the update to be sent
// to the global nameServer for processing.
func DeleteRRs(pinNames []string, keys []dns.KEY) {
	for _, domain := range pinNames {

		zone, err := GetZone(domain, nameServer)
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

// Compose a DNS Dynamic Updte to add a new TLSA RR. The process is meant to
// be additive, so that multiple records can be added. The update request is
// sent via TsigAndSend().
func AddRR(pinNames []string, keys []dns.KEY, crtSigns []string) {
	for _, domain := range pinNames {
		zone, err := GetZone(domain, nameServer)
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

// Precalculate the certificate signatures from the pinned certificates to
// use. These are suitable for setting up TLSA records without reading certs
// multiple times.
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
