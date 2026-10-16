// Command sesame-keygen prints a fresh ed25519 ticket-signing keypair: the private seed (for the broker's
// sign_key_file) and the public key hex (for the egress public_keys). Also mints dev identity tokens for local
// testing with --dev-token.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vladinsc/sesame/connectors/identity/dev"
)

func main() {
	devToken := flag.String("dev-token", "", "mint a dev token: sub,secretfile[,group1,group2,...]")
	ttl := flag.Duration("ttl", time.Hour, "dev token lifetime")
	flag.Parse()

	if *devToken != "" {
		mintDevToken(*devToken, *ttl)
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail(err)
	}
	fmt.Printf("# ed25519 ticket signing keypair\n")
	fmt.Printf("sign_key_file seed (hex): %s\n", hex.EncodeToString(priv.Seed()))
	fmt.Printf("public key (hex):         %s\n", hex.EncodeToString(pub))
}

func mintDevToken(spec string, ttl time.Duration) {
	parts := strings.Split(spec, ",")
	if len(parts) < 2 {
		fail(fmt.Errorf("want sub,secretfile[,groups...]"))
	}
	sub, secretFile, groups := parts[0], parts[1], parts[2:]
	secret, err := os.ReadFile(secretFile)
	if err != nil {
		fail(err)
	}
	id := dev.New([]byte(strings.TrimSpace(string(secret))), "", "")
	fmt.Println(id.Mint(dev.Token{Sub: sub, Email: sub + "@example", Groups: groups, Exp: time.Now().Add(ttl).Unix()}))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sesame-keygen:", err)
	os.Exit(1)
}
