package authstore

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestTransportProfilePublicMetadata(t *testing.T) {
	// A public, constructed odd modulus exercises parsing; this is not a server key.
	modulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	modulus.Add(modulus, big.NewInt(1))
	profile := TransportProfile{Version: 1, CoreVersion: "public-test-core", Modulus: modulus.String(), Exponent: "65537"}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDirectory(t), "transport.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTransportProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := loaded.PublicKey()
	if err != nil || key.E != 65537 || key.N.Cmp(modulus) != 0 {
		t.Fatal("public key metadata did not survive loading")
	}
	profile.Modulus = "0x" + modulus.Text(16)
	profile.Exponent = "0x10001"
	if key, err := profile.PublicKey(); err != nil || key.N.Cmp(modulus) != 0 || key.E != 65537 {
		t.Fatal("hexadecimal public integers were not supported")
	}
}

func TestTransportProfileRejectsInvalidKeys(t *testing.T) {
	modulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	modulus.Add(modulus, big.NewInt(1))
	for _, profile := range []TransportProfile{
		{Modulus: "7", Exponent: "65537"},
		{Modulus: modulus.String(), Exponent: "2"},
		{Modulus: modulus.String(), Exponent: "0xnot-an-integer"},
		{Modulus: "-" + modulus.String(), Exponent: "65537"},
		{Modulus: modulus.String(), Exponent: "4294967295"},
	} {
		if _, err := profile.PublicKey(); err == nil {
			t.Fatal("invalid public key was accepted")
		}
	}
}
