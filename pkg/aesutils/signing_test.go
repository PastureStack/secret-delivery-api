// Added by PastureStack in 2026: malformed-signature regression coverage.
package aesutils

import (
	"encoding/base64"
	"testing"
)

func TestVerifySignatureRejectsShortPayload(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	shortSignature := base64.StdEncoding.EncodeToString([]byte("short"))

	verified, err := VerifySignature(key, shortSignature, "message")
	if err == nil {
		t.Fatal("expected malformed signature error")
	}
	if verified {
		t.Fatal("malformed signature must not verify")
	}
}

func TestVerifySignatureRejectsMissingSeparator(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	malformed := base64.StdEncoding.EncodeToString([]byte("012345678901xpayload"))

	verified, err := VerifySignature(key, malformed, "message")
	if err == nil {
		t.Fatal("expected malformed signature error")
	}
	if verified {
		t.Fatal("malformed signature must not verify")
	}
}

func TestSignAndVerifyRoundTripAndTamper(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	signature, err := Sign(key, "message")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignature(key, signature, "message")
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("valid signature did not verify")
	}
	verified, err = VerifySignature(key, signature, "tampered")
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("tampered message verified")
	}
}

func TestVerifySignatureRejectsWrongDigestLength(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	malformed := base64.StdEncoding.EncodeToString(append([]byte("012345678901:"), make([]byte, 31)...))
	if verified, err := VerifySignature(key, malformed, "message"); err == nil || verified {
		t.Fatal("expected wrong digest length to be rejected")
	}
}
