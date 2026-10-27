package clientapi

import "testing"

func TestSynchronizedEmptyNodesRemainDistinctFromMissingNodes(t *testing.T) {
	for _, servers := range []string{"[]", "{}"} {
		t.Run(servers, func(t *testing.T) {
			full := []byte(`{"SyncVersion":{"Login":1,"Servers":2},"Login":{"AuthResult":"OK","LoginToken":"public-empty-token"},"Servers":` + servers + `}`)
			prior, err := parseLoginResponse(full, "public-empty-account")
			if err != nil || prior.Nodes == nil || len(prior.Nodes) != 0 {
				t.Fatal("full synchronization lost the known empty list")
			}
			unchanged := []byte(`{"SyncVersion":{"Login":1,"Servers":2}}`)
			updated, err := parseSyncResponse(unchanged, prior.Username, &prior)
			if err != nil || updated.Nodes == nil || len(updated.Nodes) != 0 {
				t.Fatal("incremental synchronization lost the known empty list")
			}
			// Pre-fix empty caches omitted Nodes while retaining the Servers version.
			prior.Nodes = nil
			updated, err = parseSyncResponse(unchanged, prior.Username, &prior)
			if err != nil || updated.Nodes == nil || len(updated.Nodes) != 0 || prior.Nodes != nil {
				t.Fatal("legacy empty cache did not normalize without mutating prior")
			}
		})
	}
	missing, err := parseLoginResponse([]byte(`{"Login":{"AuthResult":"OK","LoginToken":"public-minimal-token"}}`), "public-account")
	if err != nil || missing.Nodes != nil {
		t.Fatal("unsynchronized session was incorrectly treated as an empty node cache")
	}
}
