package merkle

import "testing"

func TestMerkleProof(t *testing.T) {
	leaves := [][]byte{[]byte("tx1"), []byte("tx2"), []byte("tx3"), []byte("tx4")}
	tree := Build(leaves)
	root := tree.Root()
	proof := tree.Proof(2)
	if !Verify([]byte("tx3"), proof, root) {
		t.Fatal("expected tx3 proof to verify")
	}
	if Verify([]byte("evil"), proof, root) {
		t.Fatal("tampered leaf should not verify")
	}
}
