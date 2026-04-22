package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/chenzhangda16/eth-crypto-miniclosure/internal/ethhash"
	"github.com/chenzhangda16/eth-crypto-miniclosure/internal/merkle"
	"github.com/chenzhangda16/eth-crypto-miniclosure/internal/abiutil"
	"github.com/chenzhangda16/eth-crypto-miniclosure/internal/ethcrypto"
)

func main() {
	key := ethcrypto.MustDeterministicKeyFromSeed("alice")
	addr := ethcrypto.AddressFromPrivateKey(key)
	msg := []byte("I authorize this action")
	sig, _ := ethcrypto.SignPersonalMessage(key, msg)
	calldata, _ := abiutil.EncodeTransferCalldata("0x1111111111111111111111111111111111111111", big.NewInt(1000))

	fmt.Println("== key / address ==")
	fmt.Println("private key:", ethcrypto.PrivateKeyHex(key))
	fmt.Println("public key :", ethcrypto.PublicKeyHex(&key.PublicKey))
	fmt.Println("address    :", addr)
	fmt.Println()

	fmt.Println("== hash / sign ==")
	fmt.Println("keccak(hello):", ethhash.Keccak256Hex([]byte("hello")))
	fmt.Println("personal hash :", hex.EncodeToString(ethcrypto.PersonalMessageHash(msg)))
	fmt.Println("sig(asn1)     :", hex.EncodeToString(sig))
	fmt.Println("verify        :", ethcrypto.VerifyPersonalSignature(&key.PublicKey, msg, sig))
	fmt.Println()

	fmt.Println("== abi / topics ==")
	fmt.Println("selector transfer(address,uint256):", abiutil.FunctionSelectorHex("transfer(address,uint256)"))
	fmt.Println("topic0 Transfer(address,address,uint256):", abiutil.EventTopicHex("Transfer(address,address,uint256)"))
	fmt.Println("calldata transfer(to,1000):", calldata)
	fmt.Println()

	fmt.Println("== merkle ==")
	tree := merkle.Build([][]byte{[]byte("tx1"), []byte("tx2"), []byte("tx3"), []byte("tx4")})
	proof := tree.Proof(2)
	fmt.Println("root:", hex.EncodeToString(tree.Root()))
	fmt.Println("proof nodes:", len(proof))
	fmt.Println("verify tx3:", merkle.Verify([]byte("tx3"), proof, tree.Root()))
}
