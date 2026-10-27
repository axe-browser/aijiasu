package authstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aijiasu-native/internal/native/clientapi"
)

func TestSessionRoundTripPreservesEmptyNodeCacheAndLegacyVersions(t *testing.T) {
	for _, scenario := range []string{"minimal", "empty", "legacy-empty"} {
		t.Run(scenario, func(t *testing.T) {
			directory := privateDirectory(t)
			session := publicSession()
			if scenario == "empty" {
				session.Nodes = []clientapi.Node{}
			}
			if scenario == "legacy-empty" {
				session.SyncVersion = map[string]string{"Login": "1", "Servers": "2"}
			}
			if scenario == "legacy-empty" {
				// Simulate an old omitted empty list, bypassing the new serializer.
				data, err := json.Marshal(session)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, sessionFileName), data, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := SaveSession(directory, session); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadSession(directory)
			if err != nil {
				t.Fatal(err)
			}
			if (loaded.Nodes == nil) != (scenario == "minimal") || len(loaded.Nodes) != 0 {
				t.Fatal("stored node-cache synchronization state did not round-trip")
			}
			version, err := VersionOfSession(directory, loaded)
			if err != nil {
				t.Fatal("normalized session version could not be captured")
			}
			loaded.LoginToken = "updated-public-empty-token"
			if err := SaveRefreshedSession(directory, version, loaded); err != nil {
				t.Fatal("normalized empty cache could not refresh conditionally")
			}
			data, err := os.ReadFile(filepath.Join(directory, sessionFileName))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			_, present := fields["nodes"]
			if present != (scenario != "minimal") || present && string(fields["nodes"]) != "[]" {
				t.Fatal("serializer omitted a known empty cache or invented one for a minimal session")
			}
		})
	}
}
