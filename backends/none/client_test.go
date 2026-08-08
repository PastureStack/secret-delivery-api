package none

import "testing"

func TestCompatibilityClientRoundTripAndSignature(t *testing.T) {
	client := &Client{}
	encrypted, err := client.GetEncryptedText("", "legacy value")
	if err != nil {
		t.Fatal(err)
	}
	clearText, err := client.GetClearText("", encrypted)
	if err != nil || clearText != "legacy value" {
		t.Fatalf("unexpected clear text %q: %v", clearText, err)
	}
	signature, err := client.Sign("", clearText)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("expected a SHA-256 signature, got %d hexadecimal characters", len(signature))
	}
	verified, err := client.VerifySignature("", signature, clearText)
	if err != nil || !verified {
		t.Fatalf("compatibility signature did not verify: %v, %v", verified, err)
	}
	verified, err = client.VerifySignature("", signature, "tampered")
	if err != nil || verified {
		t.Fatalf("tampered compatibility signature result: %v, %v", verified, err)
	}
	const legacyMD5Signature = "2bbb816f1aa9abfdf9b8af81ca2c9199"
	verified, err = client.VerifySignature("", legacyMD5Signature, clearText)
	if err != nil || verified {
		t.Fatalf("legacy MD5 signature must be rejected: %v, %v", verified, err)
	}
	if _, err := client.VerifySignature("", "not hexadecimal", clearText); err == nil {
		t.Fatal("expected malformed signature error")
	}
	if err := client.Delete("", encrypted); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibilityClientRejectsMalformedBase64(t *testing.T) {
	if _, err := (&Client{}).GetClearText("", "not base64!"); err == nil {
		t.Fatal("expected malformed base64 error")
	}
}
