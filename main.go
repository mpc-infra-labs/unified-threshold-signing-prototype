package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"mpc-go-demo/pkg/mpc"
)

const KeyFile = "mpc_solana_shares.json"

// Custom local keystore structure for this prototype.
type SolanaKeyStore struct {
	Address string `json:"address"`
	// Serialized threshold shares persisted for signing.
	Share1  mpc.FrostShare `json:"share1"`
	Share3  mpc.FrostShare `json:"share3"`
	PubKey  []byte         `json:"pubkey_bytes"`
}

func main() {
	fmt.Println("========================================")
	fmt.Println("   Solana MPC Wallet   ")
	fmt.Println("========================================")
	fmt.Println("1. Run Distributed Key Generation (DKG)")
	fmt.Println("2. Sign Transaction (Solana)")

	fmt.Print("\nSelect option: ")
	var choice string
	fmt.Scanln(&choice)

	switch choice {
	case "1":
		runDKG()
	case "2":
		runSign()
	default:
		fmt.Println("Invalid option")
	}
}

// 1) DKG flow
func runDKG() {
	fmt.Println("\n[DKG] Starting 2-of-3 Key Generation...")

	// Reuse the DKG logic implemented in mpc/frost_math.go.
	shares, pubBytes := mpc.DKG()

	// Build a display address from the public key.
	// This demo prints hex; production code should use Base58 for Solana UX.
	address := hex.EncodeToString(pubBytes)

	store := SolanaKeyStore{
		Address: address,
		Share1:  shares["1"],
		Share3:  shares["3"],
		PubKey:  pubBytes,
	}

	saveJson(KeyFile, store)
	fmt.Printf("DKG Success!\n")
	fmt.Printf("   Public Key (Hex): %s\n", address)
	fmt.Printf("   Shares saved to %s\n", KeyFile)
}

// 2) Threshold signing flow
func runSign() {
	fmt.Println("\n[Sign] Starting MPC Signature...")

	// Load persisted shares and group public key.
	var store SolanaKeyStore
	if !loadJson(KeyFile, &store) {
		return
	}

	// Simulate a transaction payload.
	msg := []byte("Solana Transaction Data 12345")
	fmt.Printf("   Message: %s\n", msg)

	// Run threshold signing with share 1 and share 3.
	sig, err := mpc.Sign(store.Share1, store.Share3, msg)
	if err != nil {
		fmt.Printf("Sign Error: %v\n", err)
		return
	}

	fmt.Printf("✅ Signature Generated (64 bytes):\n%x\n", sig)

	// Verify signature locally.
	isValid := ed25519.Verify(store.PubKey, msg, sig)
	if isValid {
		fmt.Println("Local Verification: VALID")
	} else {
		fmt.Println("Local Verification: INVALID")
	}
}

// --- File helpers ---

func saveJson(filename string, v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(filename, data, 0600)
}

func loadJson(filename string, v interface{}) bool {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Could not load %s. Please run DKG first.\n", filename)
		return false
	}
	json.Unmarshal(data, v)
	return true
}