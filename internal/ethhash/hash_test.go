package ethhash

import "testing"

func TestKeccak256KnownVector(t *testing.T) {
	got := Keccak256Hex([]byte("hello"))
	want := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if got != want {
		t.Fatalf("unexpected keccak256(hello): got %s want %s", got, want)
	}
}
