package main

import "aijiasu-native/internal/native/clientapi"

func configuredTLSPin(profile clientapi.Profile, override string) string {
	if override != "" {
		return override
	}
	return profile.TLSSPKISHA256
}
