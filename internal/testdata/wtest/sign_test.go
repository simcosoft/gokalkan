package wtest

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestHash(t *testing.T) {
	data := []byte("test")
	wantSHA256 := sha256.Sum256(data)

	gotSHA256, err := cli.HashSHA256(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSHA256, wantSHA256[:]) {
		t.Errorf("SHA-256 = %x; want %x", gotSHA256, wantSHA256)
	}

	gotGOST, err := cli.HashGOST95(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotGOST) == 0 {
		t.Error("GOST hash is empty")
	}
}

func TestSign(t *testing.T) {
	data := []byte("test")

	gotSignedData, err := cli.Sign(data, false, false)
	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}

	_, err = cli.Verify(gotSignedData)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignXML(t *testing.T) {
	data := "<test>data</test>"

	gotSignedData, err := cli.SignXML(data)
	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}

	_, err = cli.VerifyXML(gotSignedData)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignWSEE(t *testing.T) {
	gotSignedData, err := cli.SignWSSE("<test>data</test>", "id-12345")
	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}
	_, err = cli.VerifyXML(gotSignedData)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignDetached(t *testing.T) {
	data := []byte("test")

	gotSignedData, err := cli.Sign(data, true, false)
	if err != nil {
		t.Fatalf("%s: %s", key.Alias, err)
	}

	_, err = cli.VerifyDetached(gotSignedData, data)
	if err != nil {
		t.Fatal(err)
	}
}
