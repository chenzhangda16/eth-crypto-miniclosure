package ethcrypto

import "testing"

func TestDeterministicKeyAddressAndSignature(t *testing.T) {
	key := MustDeterministicKeyFromSeed("alice")
	addr := AddressFromPrivateKey(key)
	if len(addr) != 42 || addr[:2] != "0x" {
		t.Fatalf("invalid address format: %s", addr)
	}
	msg := []byte("I authorize this action")
	sig, err := SignPersonalMessage(key, msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if !VerifyPersonalSignature(&key.PublicKey, msg, sig) {
		t.Fatal("signature should verify")
	}
	if VerifyPersonalSignature(&key.PublicKey, []byte("tampered"), sig) {
		t.Fatal("signature should fail for tampered message")
	}
}
