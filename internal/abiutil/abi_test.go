package abiutil

import (
	"math/big"
	"testing"
)

func TestFunctionSelectorAndEventTopic(t *testing.T) {
	if got, want := FunctionSelectorHex("transfer(address,uint256)"), "a9059cbb"; got != want {
		t.Fatalf("selector mismatch: got %s want %s", got, want)
	}
	if got, want := EventTopicHex("Transfer(address,address,uint256)"), "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"; got != want {
		t.Fatalf("topic mismatch: got %s want %s", got, want)
	}
}
func TestEncodeTransferCalldata(t *testing.T) {
	got, err := EncodeTransferCalldata("0x1111111111111111111111111111111111111111", big.NewInt(1000))
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	want := "0xa9059cbb" +
		"0000000000000000000000001111111111111111111111111111111111111111" +
		"00000000000000000000000000000000000000000000000000000000000003e8"
	if got != want {
		t.Fatalf("calldata mismatch:\n got  %s\n want %s", got, want)
	}
}
