# gokalkan

This repository is a fork of [github.com/gokalkan/gokalkan](https://github.com/gokalkan/gokalkan).

The `gokalkan` package is a wrapper around the native methods of the KalkanCrypt library.

KalkanCrypt is the primary library for working with digital signature keys from pki.gov.kz.
It can sign and verify data, extract information, and perform other operations involving
electronic signatures, digital certificates, and keys.

Features of the `gokalkan` package:

- Multithreading support
- No dependencies
- Clean code
- Calls KalkanCrypt native methods directly

## Before You Begin

Some setup is required before using the library:

For Docker deployments, we recommend using a Debian image. Projects using this package have run successfully on Debian, while issues have been encountered with Alpine.

#### 1. Get the SDK

Contact [pki.gov.kz](https://pki.gov.kz/developers/) to obtain the SDK. It includes libraries for Java and C.

#### 2. Install CA certificates

The certificates are located in `SDK/C/Linux/ca-certs/Ubuntu`. The directory contains `production` and `test` certificates, along with scripts to install them. Running the scripts requires `sudo` privileges.

#### 3. Copy the .so files

The files are located in `SDK 2.0/C/Linux/C/libs/v2.0.4`. Copy them with:

```sh
sudo cp -f libkalkancryptwr-64.so.2.0.4 /usr/lib/libkalkancryptwr-64.so
```

## Installation

Go 1.27 or later

```sh
go get github.com/simcosoft/gokalkan
```

## Package Functions

### Creating and configuring a client

| Function | Description |
| --- | --- |
| `NewClient(opts ...Option)` | Creates and initializes a KalkanCrypt client with the specified options. |
| `OptsProd`, `OptsTest` | Preset options for the production and test TSP and OCSP services. Pass one of these to `NewClient`. |
| `WithLogger(logger Logger)` | Sets the client's logger. |
| `WithTSP(url string)` | Sets the timestamp service URL. |
| `WithOCSP(url string)` | Sets the certificate status service URL. |
| `WithCert(cert, typ)` | Adds a CA or intermediate certificate to the client options. |
| `WithCerts(certs)` | Sets the list of certificates to be loaded by the client. |
| `WithRemoteProdCerts(ctx)` | Downloads production PKI certificates and adds them to the client options. |
| `WithRemoteTestCerts(ctx)` | Downloads test PKI certificates and adds them to the client options. |
| `(*Client).Options()` | Returns the client's current options. |

### Keys and certificates

| Function | Description |
| --- | --- |
| `(*Client).LoadKeyStore(path, password)` | Loads a PKCS#12 keystore from a file. |
| `(*Client).LoadKeyStoreFromBytes(key, password)` | Loads a PKCS#12 keystore from bytes. |
| `(*Client).LoadCerts()` | Loads the certificates configured when the client was created. |
| `(*Client).LoadCertFromBytes(cert, certType)` | Loads a certificate from bytes, such as a CA or intermediate certificate. |
| `(*Client).GetCertFromCMS(cms, signID)` | Extracts a signer's certificate from a CMS signature. `signID` specifies the signer index. |
| `(*Client).GetCertFromXML(xml, signID)` | Extracts a signer's certificate from an XML signature. |
| `(*Client).ValidateCert(cert)` | Validates a certificate without making an OCSP request. |
| `(*Client).ValidateCertOCSP(cert, url...)` | Checks a certificate's status using OCSP. An optional service URL can be provided. |
| `(*Client).X509CertificateGetInfo(cert, prop)` | Returns the selected certificate field. The certificate must be in PEM format. |
| `(*Client).X509CertificateGetSummary(cert)` | Returns structured certificate information, including subject and issuer details, validity period, and serial number. If inspecting a certificate from a signature, call `Verify` first. |

### Signing and verification

| Function | Description |
| --- | --- |
| `(*Client).Sign(data, isDetached, withTSP)` | Creates a CMS signature. The parameters control whether the signature is detached and whether to include a timestamp. |
| `(*Client).SignWithFlags(data, flags)` | Signs data with the specified KalkanCrypt flags and returns the key certificate. Uses the `pkiKey` key from the loaded keystore. |
| `(*Client).SignXML(xml)` | Signs an XML document. |
| `(*Client).SignWSSE(xml, id)` | Signs XML using WS-Security, placing it in the SOAP Body with the specified ID. |
| `WrapWithWSSESoapEnvelope(xml, id)` | Wraps an XML document in a SOAP Envelope and Body with a WS-Security ID. |
| `(*Client).Verify(signature)` | Verifies a CMS signature and returns the result information. |
| `(*Client).VerifyDetached(signature, data)` | Verifies a detached CMS signature against the provided data. |
| `(*Client).VerifyXML(signedXML)` | Verifies an XML signature and returns the result information. |

### Hashing and utility methods

| Function | Description |
| --- | --- |
| `(*Client).HashSHA256(data)` | Computes the SHA-256 hash of the data. |
| `(*Client).HashGOST95(data)` | Computes the hash using GOST 34.11-95. |
| `(*Client).GetTimeFromSig(signature, signID)` | Gets the signing time for the specified signer. |
| `(*Client).Underlying()` | Returns the underlying `ckalkan` client for direct access to KalkanCrypt methods. |
| `(*Client).Close()` | Releases the client's resources. Call this when finished. |

## Loading a PKCS#12 Keystore

Load a keystore containing a key and certificate (for example, an e-signature key whose name starts with `RSA...`):

```go
package main

import (
	"fmt"
	"log"

	"github.com/simcosoft/gokalkan"
)

var (
	certPath = "test_cert/GOSTKNCA.p12" // path to the keystore

	certPassword = "Qwerty12" // password
	// Never store passwords in source code.
)

func main() {
	// For testing
	opts := gokalkan.OptsTest

	// For production
	// opts := gokalkan.OptsProd

	cli, err := gokalkan.NewClient(opts...)
	if err != nil {
		log.Fatal("new kalkan client create error", err)
	}
	// Always close the client to avoid resource leaks.
	defer cli.Close()

	// Load the keystore with its password.
	err = cli.LoadKeyStore(certPath, certPassword)
	if err != nil {
		log.Fatal("load key store error", err)
	}
}
```

When initializing a `gokalkan` client, pass an option. The package provides `OptsTest` and `OptsProd`; choose one based on your environment.

### Signing an XML document

To sign an XML document, pass it as a string:

```go
signedXML, err := cli.SignXML("<root>GoKalkan</root>")

fmt.Println("Signed XML:", signedXML)
fmt.Println("Error:", err)
```

### Verifying an XML signature

Verification returns an error if the document has an invalid signature or the signing certificate has expired.

```go
serial, err := cli.VerifyXML(signedXML)

fmt.Println("Serial number:", serial)
fmt.Println("Error:", err)
```

### Signing an XML document for SmartBridge

To sign an XML document in WS-Security format, pass the document as a string and provide an ID for the SOAP Body. The function wraps the document in a `soap:Envelope` and places it inside the `soap:Body`.

```go
signedXML, err := cli.SignWSSE("<root>gokalkan</root>", "12345")

fmt.Println("WS-Security signed XML:", signedXML)
fmt.Println("Error:", err)
```

### Getting the signing time for the second signer

```go
signTime, err := c.GetTimeFromSig(cmsFileBody, 1)

fmt.Println("Signing time:", signTime)
fmt.Println("Error:", err)
```

### Getting a field from a certificate
The certificate must be in PEM format.

```go
value, err := c.X509CertificateGetInfo(certBody, ckalkan.CertPropSubjectCommonName)

fmt.Println("Value:", value)
fmt.Println("Error:", err)
```

### Getting a certificate summary
The certificate must be in PEM format.

```go
info, err := c.X509CertificateGetSummary(certBody)

fmt.Println("Information:", info)
fmt.Println("Error:", err)
```

## Tests

Run all unit and integration tests with:

```sh
make test
```

The integration tests use the KalkanCrypt native library and test PKCS#12 fixtures. They also contact the test PKI OCSP service, so the native library must be installed and network access to the test PKI is required. The test packages are under directories named `testdata`, which `go test ./...` skips; use `make test` to run them.

To run only the wrapper integration tests, use `make wtest`.


## License

The MIT License (MIT) 2021 - [Abylaikhan Zulbukharov](https://github.com/Zulbukharov).

Please have a look at the [LICENSE.md](https://github.com/Zulbukharov/kalkancrypt-wrapper/blob/master/LICENSE.md) for more details.
