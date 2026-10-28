package ckalkan

import (
	"errors"
	"fmt"
	"testing"
)

func TestGetErrorCode(t *testing.T) {
	er := KalkanError{
		errorCode:   ErrorCodeCertParseError,
		errorString: "test",
	}

	got, ok := GetErrorCode(er)
	if !ok {
		t.Fatal("expected true")
	}

	if got != ErrorCodeCertParseError {
		t.Fatal("mismatch eror code")
	}

	er2 := &KalkanError{
		errorCode:   ErrorCodeCheckChainError,
		errorString: "test",
	}

	got, ok = GetErrorCode(er2)
	if !ok {
		t.Fatal("expected true")
	}

	if got != ErrorCodeCheckChainError {
		t.Fatal("mismatch eror code")
	}
}

func TestErrorCodeFormatting(t *testing.T) {
	if got := ErrorCodeCertParseError.String(); got != "Невозможно разобрать (распарсить) сертификат" {
		t.Fatalf("String() = %q", got)
	}
	if got := ErrorCode(999999).String(); got != "Неизвестный код ошибки" {
		t.Fatalf("unknown String() = %q", got)
	}
	if got := ErrorCodeCertParseError.Hex(); got != "8f00006" {
		t.Fatalf("Hex() = %q", got)
	}
}

func TestKalkanErrorFormattingAndWrappedCode(t *testing.T) {
	err := KalkanError{
		errorCode:   ErrorCodeCertParseError,
		errorString: "bad certificate",
	}
	if got, want := err.Error(), "[8f00006] Невозможно разобрать (распарсить) сертификат: bad certificate"; got != want {
		t.Fatalf("Error() = %q; want %q", got, want)
	}

	wrapped := fmt.Errorf("outer: %w", err)
	if got, ok := GetErrorCode(wrapped); !ok || got != ErrorCodeCertParseError {
		t.Fatalf("GetErrorCode(wrapped) = %v, %t", got, ok)
	}
	if _, ok := GetErrorCode(errors.New("unrelated")); ok {
		t.Fatal("GetErrorCode unexpectedly recognized an unrelated error")
	}
}
