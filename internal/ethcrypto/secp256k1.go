package ethcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"eth-crypto-miniclosure/internal/ethhash"
)

var secp256k1 elliptic.Curve

func init() {
	params := &elliptic.CurveParams{Name: "secp256k1"}
	params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	params.B = big.NewInt(7)
	params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	params.BitSize = 256
	secp256k1 = params
}

func GenerateKey() (*ecdsa.PrivateKey, error)    { return ecdsa.GenerateKey(secp256k1, rand.Reader) }
func PrivateKeyHex(key *ecdsa.PrivateKey) string { return fmt.Sprintf("%064x", key.D) }

func PublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	full := elliptic.Marshal(secp256k1, pub.X, pub.Y)
	return full[1:]
}
func PublicKeyHex(pub *ecdsa.PublicKey) string { return hex.EncodeToString(PublicKeyBytes(pub)) }

func AddressFromPublicKey(pub *ecdsa.PublicKey) string {
	hash := ethhash.Keccak256(PublicKeyBytes(pub))
	return "0x" + hex.EncodeToString(hash[12:])
}
func AddressFromPrivateKey(key *ecdsa.PrivateKey) string { return AddressFromPublicKey(&key.PublicKey) }

func PersonalMessageHash(message []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	return ethhash.Keccak256([]byte(prefix), message)
}

func SignPersonalMessage(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := PersonalMessageHash(message)
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
func VerifyPersonalSignature(pub *ecdsa.PublicKey, message, sig []byte) bool {
	digest := PersonalMessageHash(message)
	return ecdsa.VerifyASN1(pub, digest, sig)
}

func DeterministicKeyFromSeed(seed string) (*ecdsa.PrivateKey, error) {
	sum := sha256.Sum256([]byte(seed))
	n := new(big.Int).Sub(secp256k1.Params().N, big.NewInt(1))
	d := new(big.Int).SetBytes(sum[:])
	d.Mod(d, n)
	d.Add(d, big.NewInt(1))
	key := &ecdsa.PrivateKey{}
	key.PublicKey.Curve = secp256k1
	key.D = d
	key.PublicKey.X, key.PublicKey.Y = secp256k1.ScalarBaseMult(d.Bytes())
	if key.PublicKey.X == nil {
		return nil, fmt.Errorf("failed to derive deterministic key")
	}
	return key, nil
}
func MustDeterministicKeyFromSeed(seed string) *ecdsa.PrivateKey {
	k, err := DeterministicKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}
func NormalizeAddress(addr string) string { return strings.ToLower(addr) }
