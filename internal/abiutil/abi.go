package abiutil

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"eth-crypto-miniclosure/internal/ethhash"
)

func FunctionSelector(signature string) []byte { return ethhash.Keccak256([]byte(signature))[:4] }
func FunctionSelectorHex(signature string) string {
	return hex.EncodeToString(FunctionSelector(signature))
}
func EventTopic(signature string) []byte    { return ethhash.Keccak256([]byte(signature)) }
func EventTopicHex(signature string) string { return hex.EncodeToString(EventTopic(signature)) }

func EncodeAddress(addr string) ([]byte, error) {
	clean := strings.TrimPrefix(strings.ToLower(addr), "0x")
	if len(clean) != 40 {
		return nil, fmt.Errorf("address must be 20 bytes, got %d hex chars", len(clean))
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("decode address: %w", err)
	}
	out := make([]byte, 32)
	copy(out[12:], raw)
	return out, nil
}
func EncodeUint256(v *big.Int) ([]byte, error) {
	if v.Sign() < 0 {
		return nil, fmt.Errorf("uint256 cannot be negative")
	}
	if v.BitLen() > 256 {
		return nil, fmt.Errorf("value overflows uint256")
	}
	out := make([]byte, 32)
	vb := v.Bytes()
	copy(out[32-len(vb):], vb)
	return out, nil
}
func EncodeTransferCalldata(to string, amount *big.Int) (string, error) {
	selector := FunctionSelector("transfer(address,uint256)")
	encTo, err := EncodeAddress(to)
	if err != nil {
		return "", err
	}
	encAmount, err := EncodeUint256(amount)
	if err != nil {
		return "", err
	}
	payload := append(selector, encTo...)
	payload = append(payload, encAmount...)
	return "0x" + hex.EncodeToString(payload), nil
}
