package wtest

import (
	"fmt"
	"testing"
	"time"

	"github.com/simcosoft/gokalkan"
	"github.com/simcosoft/gokalkan/ckalkan"
)

func TestGetCertFromCMS(t *testing.T) {
	data := []byte("test")

	cms, err := cli.Sign(data, false, false)
	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}

	gotCrt, err := cli.GetCertFromCMS(cms, 1)
	if err != nil {
		t.Fatal(err)
	}

	if gotCrt != key.Cert {
		fmt.Printf("\ngot cert: \n<<<%s>>>\n", gotCrt)
		fmt.Printf("\nexp cert: \n<<<%s>>>\n", key.Cert)
		t.Fatal(key.Alias, " cert mismatch")
	}
}

func TestGetCertFromXML(t *testing.T) {
	xml, err := cli.SignXML("<root>GoKalkan</root>")

	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}

	gotCrt, err := cli.GetCertFromXML(xml, 1)

	if err != nil {
		t.Fatal(err)
	}
	gotCrtStr := "-----BEGIN CERTIFICATE-----\n" + string(gotCrt[:]) + "\n-----END CERTIFICATE-----\n"

	if gotCrtStr != key.Cert {
		fmt.Printf("\ngot cert: \n<<<%s>>>\n", gotCrt)
		fmt.Printf("\nexp cert: \n<<<%s>>>\n", key.Cert)
		t.Fatal(key.Alias, " cert mismatch")
	}
}

func TestX509CertificateGetSummary(t *testing.T) {
	commonName, err := cli.X509CertificateGetInfo(key.Cert, ckalkan.CertPropSubjectCommonName)
	if err != nil {
		t.Fatal(err)
	}
	if commonName == "" {
		t.Error("certificate common name is empty")
	}

	summary, err := cli.X509CertificateGetSummary(key.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Type != gokalkan.CertTypeIndividual {
		t.Fatalf("certificate type = %q; want %q", summary.Type, gokalkan.CertTypeIndividual)
	}
	if summary.Subject.IIN != "123456789011" {
		t.Errorf("subject IIN = %q", summary.Subject.IIN)
	}
	if summary.NotBefore.Year() != 2026 || summary.NotAfter.Year() != 2027 {
		t.Errorf("validity = %v through %v", summary.NotBefore, summary.NotAfter)
	}
	wantNotAfter := time.Date(2027, time.May, 8, 7, 45, 13, 0, time.UTC)
	if !summary.NotAfter.Equal(wantNotAfter) {
		t.Errorf("NotAfter = %v; want %v", summary.NotAfter, wantNotAfter)
	}
	if summary.Organization != nil {
		t.Errorf("individual certificate has organization data: %+v", summary.Organization)
	}
}
