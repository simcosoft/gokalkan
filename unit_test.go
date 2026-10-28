package gokalkan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simcosoft/gokalkan/ckalkan"
)

type testLogger struct{}

func (testLogger) Debug(...interface{}) {}
func (testLogger) Error(...interface{}) {}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTripper roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

func TestOptionsAndDefaults(t *testing.T) {
	var nilOptions *Options
	nilOptions.setDefaults()

	options := Options{OCSP: "custom-ocsp"}
	options.setDefaults()
	if options.TSP != prodTSP || options.OCSP != "custom-ocsp" || !options.LoadCerts {
		t.Fatalf("unexpected defaults: %+v", options)
	}

	cert := &x509.Certificate{}
	logger := testLogger{}
	WithLogger(logger)(&options)
	WithTSP("custom-tsp")(&options)
	WithOCSP("custom-ocsp-2")(&options)
	WithCert(cert, ckalkan.CertTypeCA)(&options)
	if options.log != logger || options.TSP != "custom-tsp" || options.OCSP != "custom-ocsp-2" {
		t.Fatalf("options were not applied: %+v", options)
	}
	if len(options.Certs) != 1 || options.Certs[0].Cert != cert || options.Certs[0].Type != ckalkan.CertTypeCA {
		t.Fatalf("unexpected certificates: %+v", options.Certs)
	}

	certs := []OptionsCert{{Cert: cert, Type: ckalkan.CertTypeIntermediate}}
	WithCerts(certs)(&options)
	if len(options.Certs) != 1 || options.Certs[0].Type != ckalkan.CertTypeIntermediate {
		t.Fatalf("WithCerts did not replace certificates: %+v", options.Certs)
	}

	client := Client{o: options}
	if got := client.Options(); got.TSP != options.TSP || len(got.Certs) != 1 {
		t.Fatalf("unexpected client options: %+v", got)
	}
}

func TestOptionPresets(t *testing.T) {
	testCases := []struct {
		name string
		ops  []Option
		want Options
	}{
		{name: "production", ops: OptsProd, want: Options{TSP: prodTSP, OCSP: prodOCSP}},
		{name: "test", ops: OptsTest, want: Options{TSP: testTSP, OCSP: testOCSP}},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			options := Options{}
			for _, option := range test.ops {
				option(&options)
			}
			if options.TSP != test.want.TSP || options.OCSP != test.want.OCSP || options.log == nil {
				t.Fatalf("preset produced unexpected options: %+v", options)
			}
		})
	}
}

func TestCertificateStringHelpers(t *testing.T) {
	bracketTests := []struct {
		name  string
		input string
		want  string
		found bool
	}{
		{name: "value", input: "OID (1.2.3)", want: "1.2.3", found: true},
		{name: "trim spaces", input: "OID ( value )", want: "value", found: true},
		{name: "empty", input: "OID ()", want: "", found: true},
		{name: "missing bracket", input: "OID value", found: false},
		{name: "reversed brackets", input: "OID )value(", found: false},
	}
	for _, test := range bracketTests {
		t.Run(test.name, func(t *testing.T) {
			got, found := extractValueInBrackets(test.input)
			if got != test.want || found != test.found {
				t.Fatalf("extractValueInBrackets(%q) = %q, %t; want %q, %t", test.input, got, found, test.want, test.found)
			}
		})
	}

	cleanupTests := []struct {
		input string
		sep   string
		want  string
	}{
		{input: "IIN123", sep: "IIN", want: "123"},
		{input: "plain", sep: "IIN", want: "plain"},
		{input: "IIN1IIN2", sep: "IIN", want: "IIN1IIN2"},
	}
	for _, test := range cleanupTests {
		if got := cleanupValue(test.input, test.sep); got != test.want {
			t.Errorf("cleanupValue(%q, %q) = %q; want %q", test.input, test.sep, got, test.want)
		}
	}
}

func TestParseCertificateTime(t *testing.T) {
	testCases := []struct {
		value string
		want  time.Time
	}{
		{value: "08.05.2027 12:45:13 ALMT", want: time.Date(2027, time.May, 8, 7, 45, 13, 0, time.UTC)},
		{value: "08.05.2027 12:45:13 +06:00", want: time.Date(2027, time.May, 8, 6, 45, 13, 0, time.UTC)},
	}
	for _, test := range testCases {
		got, err := parseCertificateTime(test.value)
		if err != nil {
			t.Errorf("parseCertificateTime(%q): %v", test.value, err)
			continue
		}
		if !got.Equal(test.want) {
			t.Errorf("parseCertificateTime(%q) = %v; want %v", test.value, got, test.want)
		}
	}
	if _, err := parseCertificateTime("not-a-date"); err == nil {
		t.Fatal("parseCertificateTime accepted malformed input")
	}
}

func TestWrapWithWSSESoapEnvelope(t *testing.T) {
	const bodyID = "body-1"
	got := WrapWithWSSESoapEnvelope("<test>data</test>", bodyID)

	var envelope struct {
		XMLName xml.Name
		Body    struct {
			ID      string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr"`
			Content []byte `xml:",innerxml"`
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}
	if err := xml.Unmarshal([]byte(got), &envelope); err != nil {
		t.Fatalf("invalid SOAP XML: %v", err)
	}
	if envelope.XMLName.Space != xmlnsSOAP || envelope.XMLName.Local != "Envelope" {
		t.Fatalf("unexpected root element: %+v", envelope.XMLName)
	}
	if envelope.Body.ID != bodyID || strings.TrimSpace(string(envelope.Body.Content)) != "<test>data</test>" {
		t.Fatalf("unexpected SOAP body: id=%q content=%q", envelope.Body.ID, envelope.Body.Content)
	}
}

func TestDownload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("certificate"))
		}))
		defer server.Close()

		got, err := download(context.Background(), server.URL)
		if err != nil || string(got) != "certificate" {
			t.Fatalf("download() = %q, %v", got, err)
		}
	})

	t.Run("bad status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		_, err := download(context.Background(), server.URL)
		if !errors.Is(err, ErrHTTPCli) {
			t.Fatalf("download() error = %v; want ErrHTTPCli", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := download(ctx, "http://127.0.0.1")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("download() error = %v; want context.Canceled", err)
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		if _, err := download(context.Background(), "://invalid"); err == nil {
			t.Fatal("download() unexpectedly accepted an invalid URL")
		}
	})
}

func TestRemoteCertificateOptions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	previousClient := http.DefaultClient
	requestCount := 0
	http.DefaultClient = &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(certificateDER)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = previousClient })

	testCases := []struct {
		name      string
		option    func(context.Context) Option
		caCount   int
		certCount int
	}{
		{name: "production", option: WithRemoteProdCerts, caCount: 4, certCount: 8},
		{name: "test", option: WithRemoteTestCerts, caCount: 3, certCount: 6},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			requestCount = 0
			options := Options{}
			test.option(context.Background())(&options)
			if requestCount != test.certCount || len(options.Certs) != test.certCount {
				t.Fatalf("got %d requests and %d certificates; want %d", requestCount, len(options.Certs), test.certCount)
			}
			for index, cert := range options.Certs {
				wantType := ckalkan.CertTypeIntermediate
				if index < test.caCount {
					wantType = ckalkan.CertTypeCA
				}
				matchesDER := string(cert.Cert.Raw) == string(certificateDER)
				if cert.Type != wantType || !matchesDER {
					t.Errorf("certificate %d = type %v, matching DER %t; want type %v and matching DER", index, cert.Type, matchesDER, wantType)
				}
			}
		})
	}
}
