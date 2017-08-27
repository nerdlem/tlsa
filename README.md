[![GoDoc](https://godoc.org/github.com/nerdlem/tlsa?status.svg)](https://godoc.org/github.com/nerdlem/tlsa)

# tlsa

Libraries and utilities to work with TLSA DNS RRs

This is a Go package that abstracts a few useful methods to Manage RNS TLSA record sets  via TSIG-Authenticated Dynamic Updates.

```go
import "github.com/nerdlem/tlsa"
⋮
// Read a set of TSIG keys (file with well-formed KEY DNS records)
m, err := tlsa.ReadTSIG(tsigKeyFile)
if err != nil {
	panic(fmt.Sprintf("Error processing TSIG key file: %s", err))
}
⋮
// Calculate the TLSA certificate signatures for a set of existing certificates
pinCerts := []string{"cert1.pem", "cert2.pem"}
crtSigns, err = tlsa.CertificateSignatures(pinCerts)
if err != nil {
 panic(err)
}
⋮
// Delete all TLSA records associated with names in the pinNames slice
tlsa.DeleteRRs(pinNames, m)
⋮
// Use a set of TSIG records m to pin certificates with signatures in crtSigns
// on all domains in pinNames
pinNames := []string{"domain1.example.com", "domain2.example.com"
tlsa.AddRR(pinNames, m, crtSigns)
⋮
```

# Installation

To get the package and intall accompanying programs, simply follow these steps.

```
go get github.com/nerdlem/tlsa
go install github.com/nerdlem/tlsa/tlsafromcert
```

# References

* TLSA Records [RFC-6698](https://tools.ietf.org/html/rfc6698)
* Dynamic Updates [RFC-2136](https://tools.ietf.org/html/rfc2136)
* TSIG Authentication [RFC-2845](https://www.ietf.org/rfc/rfc2845)
