package authstore

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
)

// TransportProfile binds public protocol metadata to a verified reference build.
// It contains no account password or RSA private material.
type TransportProfile struct {
	Version     int    `json:"version"`
	CoreVersion string `json:"core_version"`
	Modulus     string `json:"rsa_modulus"`
	Exponent    string `json:"rsa_exponent"`
}

func LoadTransportProfile(path string) (TransportProfile, error) {
	data, err := readPrivateFile(path, maxPrivateFileBytes)
	if err != nil {
		return TransportProfile{}, err
	}
	var profile TransportProfile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF {
		return TransportProfile{}, errors.New("invalid transport profile JSON")
	}
	if profile.Version != 1 || profile.CoreVersion == "" || len(profile.CoreVersion) > 128 ||
		strings.ContainsAny(profile.CoreVersion, "\r\n\x00") {
		return TransportProfile{}, errors.New("unsupported transport profile metadata")
	}
	if _, err := profile.PublicKey(); err != nil {
		return TransportProfile{}, err
	}
	return profile, nil
}

func (profile TransportProfile) PublicKey() (*rsa.PublicKey, error) {
	modulus, ok := parsePublicInteger(profile.Modulus)
	if !ok || modulus.Sign() <= 0 || modulus.BitLen() != 1024 || modulus.Bit(0) != 1 {
		return nil, errors.New("transport profile requires an observed 1024-bit RSA public modulus")
	}
	exponent, ok := parsePublicInteger(profile.Exponent)
	if !ok || !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 || exponent.Bit(0) != 1 {
		return nil, errors.New("transport profile has an invalid RSA public exponent")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func parsePublicInteger(text string) (*big.Int, bool) {
	if text == "" || len(text) > 1024 || strings.TrimSpace(text) != text {
		return nil, false
	}
	base := 10
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		base = 16
		text = text[2:]
	}
	return new(big.Int).SetString(text, base)
}
