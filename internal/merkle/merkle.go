package merkle

import (
	"bytes"

	"eth-crypto-miniclosure/internal/ethhash"
)

type ProofNode struct {
	Hash    []byte
	IsRight bool
}

type Tree struct {
	Leaves [][]byte
	Levels [][][]byte
}

func hashLeaf(data []byte) []byte        { return ethhash.Keccak256(data) }
func hashPair(left, right []byte) []byte { return ethhash.Keccak256(left, right) }

func Build(leaves [][]byte) *Tree {
	if len(leaves) == 0 {
		return &Tree{}
	}
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = hashLeaf(leaf)
	}
	levels := [][][]byte{cloneLevel(level)}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, hashPair(level[i], level[i+1]))
		}
		levels = append(levels, cloneLevel(next))
		level = next
	}
	return &Tree{Leaves: leaves, Levels: levels}
}
func (t *Tree) Root() []byte {
	if len(t.Levels) == 0 {
		return nil
	}
	last := t.Levels[len(t.Levels)-1]
	if len(last) == 0 {
		return nil
	}
	return append([]byte(nil), last[0]...)
}
func (t *Tree) Proof(index int) []ProofNode {
	if len(t.Levels) == 0 || index < 0 || index >= len(t.Levels[0]) {
		return nil
	}
	proof := []ProofNode{}
	cur := index
	for levelIdx := 0; levelIdx < len(t.Levels)-1; levelIdx++ {
		level := t.Levels[levelIdx]
		sibling := cur ^ 1
		if sibling < len(level) {
			proof = append(proof, ProofNode{Hash: append([]byte(nil), level[sibling]...), IsRight: sibling > cur})
		}
		cur = cur / 2
	}
	return proof
}
func Verify(leaf []byte, proof []ProofNode, root []byte) bool {
	cur := hashLeaf(leaf)
	for _, node := range proof {
		if node.IsRight {
			cur = hashPair(cur, node.Hash)
		} else {
			cur = hashPair(node.Hash, cur)
		}
	}
	return bytes.Equal(cur, root)
}
func cloneLevel(level [][]byte) [][]byte {
	out := make([][]byte, len(level))
	for i := range level {
		out[i] = append([]byte(nil), level[i]...)
	}
	return out
}
