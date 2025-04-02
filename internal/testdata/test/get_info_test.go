package test

import (
	"testing"

	"github.com/simcosoft/gokalkan/ckalkan"
)

func TestX509CertificateGetInfo(t *testing.T) {
	for _, key := range keys {
		t.Run(key.Alias, func(tt *testing.T) {
			_, err := cli.X509CertificateGetInfo(key.Cert, ckalkan.CertPropCertCN)
			if err != nil {
				tt.Fatal(err)
			}
		})
	}
}
