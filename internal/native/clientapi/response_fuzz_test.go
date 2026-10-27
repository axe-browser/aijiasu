package clientapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Parser inputs are service-controlled. In addition to rejecting malformed
// data, failures must never change the caller's reusable cached session.
func FuzzSyncResponsePreservesPriorAndBoundsOutput(f *testing.F) {
	for _, seed := range []string{
		`{"SyncVersion":{"Login":1,"Servers":2}}`,
		`{"SyncVersion":{"Login":3,"Servers":4},"Login":{"AuthResult":"OK","LoginToken":"public-fuzz-token","UserName":"public-user"},"Servers":[]}`,
		`{"Login":{"AuthResult":"DENIED"}}`,
		`{"Login":{"AuthResult":"OK","LoginToken":"public-fuzz-token"},"Servers":{"a":{"id":"1","svr":"node.example.test","par":{"fv":{"p":443}}}}}`,
		`{"Login":{"AuthResult":"OK","LoginToken":"public-fuzz-token"},"Servers":null}`,
		`null`, `[]`, `{`, `{"Login":{},"Login":null}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		prior := priorSession()
		before, err := json.Marshal(prior)
		if err != nil {
			t.Fatal("cannot prepare public session fixture")
		}
		for _, snapshot := range []*Session{nil, &prior} {
			got, parseErr := parseSyncResponse(data, testUsername, snapshot)
			if parseErr != nil {
				if !reflect.DeepEqual(got, Session{}) {
					t.Fatal("failed synchronization returned partial authentication state")
				}
				continue
			}
			if got.Username != testUsername || got.LoginToken == "" || !validNodes(got.Nodes) || validateSyncVersion(got.SyncVersion) != nil {
				t.Fatal("successful synchronization returned invalid bounded state")
			}
			if len(got.Nodes) > 0 {
				got.Nodes[0].Host = "changed.example.test"
			}
			if got.SyncVersion != nil {
				got.SyncVersion["Servers"] = "changed"
			}
		}
		after, err := json.Marshal(prior)
		if err != nil || string(before) != string(after) {
			t.Fatal("synchronization output or failure mutated the caller's cache")
		}
	})
}

func FuzzNodeResponseKeepsPortsAndFieldsBounded(f *testing.F) {
	for _, seed := range []string{
		`[]`, `{}`, `null`, `[{"id":1,"tit":"public node","svr":"node.example.test","par":{"fv":{"p":4.43e2,"u":"0"}}}]`,
		`[{"id":"public-node","par":{"fv":{"p":1e999999999}}}]`,
		`[{"id":"public-node","par":{"fv":{"p":"-1"}}}]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		nodes, err := parseNodes(data)
		if err != nil {
			if nodes != nil {
				t.Fatal("failed node response returned partial entries")
			}
			return
		}
		if nodes == nil || !validNodes(nodes) {
			t.Fatal("node response returned invalid bounded fields")
		}
	})
}
