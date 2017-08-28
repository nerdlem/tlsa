[![GoDoc](https://godoc.org/github.com/nerdlem/tlsa?status.svg)](https://godoc.org/github.com/nerdlem/tlsa)

# tlsa

Libraries and utilities to work with TLSA DNS RRs

This is a Go package that abstracts a few useful methods to Manage DNS TLSA record sets  via TSIG-Authenticated Dynamic Updates.

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
// or public key files
pinCerts := []string{"cert1.pem", "cert2.pem", "pubkey1.pem"}
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

# Using tlsafromcert to manage TLSA records

In order for `tlsafromcert` to work, you'll need your DNS zone to be configured to allow dynamic updates with `TSIG` authentication. On BIND you can add these commands to your zone definition:

```bind
   ⋮
// This is the TSIG key. This can also be found in a separate file. See dnssec-keygen(1) for
// information on generating this key file.
key "lemdotclick-ddns-update" {
  algorithm HMAC-SHA512;
  secret "secret-key-in-Base-64==";
};
   ⋮
// The actual declaration of your zone file. The important bits are that this is a master zone
// and the update-policy allows for dynamic updates.
zone "lem.click" {
  type master;
  file "path-to-your-zone-file";
  update-policy { grant lemdotclick-ddns-update zonesub ANY; };
   ⋮
};
```

`dnssec-keygen` also produces a key file. As in the case of the example above, the file would be `Klemdotclick-ddns-update.+165+<nnnn>.key` and it should contain a single `KEY` record. You'll need this file to complete `TSIG` authentication.

## Invoking tlsafromcert

`tlsafromcert` needs access to your X.509 certificates or public keys; and the `TSIG` key file to authenticate the request. You'll also need to know the IP address where your authoritative name server is listening and of course, the DNS name of the services you intend to protect with `TLSA`.

To obtain the server certificate you can use a command such as this:

```
openssl s_client -showcerts -servername lem.click -connect lem.click:443 </dev/null 2>/dev/null \
    | openssl x509 -outform pem > lem-click.pem
```

Alternatively, you can capture the public key as follows:

```
openssl s_client -showcerts -servername lem.click -connect lem.click:443 </dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout -outform pem > lem-click-key.pem
```


You can of course simply copy the right file from your server although pulling the cert from the actual web server or other service can be extremely helpful. You can easily check which DNS names are protected by this certificate as follows:

```
openssl x509 -in lem-click.pem -noout -text | grep DNS:
                DNS:blog.lem.click, DNS:lem.click
```

The following shows an example of `tlsafromcert` adding all the `TLSA` records for some names protected by the certificate:

```
$ tlsafromcert -ns ns1.lem.click:53 -names blog.lem.click,lem.click -pin-certs lem-click.pem -tsig-file my-tsig.key
$ dig +short tlsa lem.click @ns1.libertad.link
3 1 2 08AB3⋯C296C0D
```

In this case, a single certificate file was provided via the `-pin-certs` command line flag. Multiple certificates can be provided by separating the file names with a comma. In this case, multiple `TLSA` records would have been added to the DNS zone.

## Clear all TLSA records

The `--clear-all` command line option instructs `tlsafromcert` to remove all `TLSA` records associated with a domain name. By skipping the `-pin-certs` option, no `TLSA` records are added, as in the following example:

```
$ tlsafromcert -ns ns1.lem.click:53 -names blog.lem.click,lem.click -tsig-file my-tsig.key -clear-all
$ dig +short tlsa lem.click @ns1.libertad.link
$
```

# References

* TLSA Records [RFC-6698](https://tools.ietf.org/html/rfc6698)
* Dynamic Updates [RFC-2136](https://tools.ietf.org/html/rfc2136)
* TSIG Authentication [RFC-2845](https://www.ietf.org/rfc/rfc2845)
