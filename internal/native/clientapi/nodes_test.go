package clientapi

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseNodesPublicFieldsAndStableObjectOrder(t *testing.T) {
	const first = `{"id":123,"tit":"公开节点","sts":true,"svr":"node.example.test","par":{"fv":{"u":"10001","p":443}},"private_token":"must-not-be-retained"}`
	const second = `{"id":false,"tit":null,"sts":1.5,"svr":null,"par":null}`
	want := []Node{{ID: "123", Title: "公开节点", Status: "true", Host: "node.example.test", TCPPort: 443, UDPPort: 10001}, {ID: "false", Status: "1.5"}}
	for _, raw := range []string{"[" + first + "," + second + "]", `{"z":` + second + `,"a":` + first + `}`} {
		got, err := parseNodes([]byte(raw))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("nodes = %+v, error = %v", got, err)
		}
		data, err := json.Marshal(got)
		if err != nil || strings.Contains(string(data), "must-not-be-retained") || strings.Contains(string(data), "private_token") {
			t.Fatal("node DTO retained an unknown response field")
		}
	}
}

func TestParseNodesRejectsInvalidSchemasAndLimits(t *testing.T) {
	for _, raw := range []string{
		`null`, `true`, `"nodes"`, `[null]`, `[[]]`, `[1]`,
		`[{"id":{}}]`, `[{"tit":[]}]`, `[{"sts":{}}]`, `[{"svr":[]}]`,
		`[{"par":[]}]`, `[{"par":{"fv":"bad"}}]`,
		`[{"par":{"fv":{"u":-1}}}]`, `[{"par":{"fv":{"p":65536}}}]`,
		`[{"par":{"fv":{"p":"443junk"}}}]`, `[{"par":{"fv":{"p":true}}}]`,
		`[{"par":{"fv":{"p":1.5}}}]`, `[{"par":{"fv":{"p":""}}}]`,
		`[{"par":{"fv":{"p":1e999999999}}}]`,
		`[{"tit":"` + strings.Repeat("x", maxNodeFieldBytes+1) + `"}]`,
		`[` + strings.Repeat(`{},`, maxNodes) + `{}` + `]`,
	} {
		nodes, err := parseNodes([]byte(raw))
		if !errors.Is(err, ErrInvalidResponse) || nodes != nil {
			t.Fatalf("invalid schema returned nodes or wrong error: %v", err)
		}
	}
}

func TestPortConversions(t *testing.T) {
	for raw, want := range map[string]int{"null": 0, "0": 0, "65535": 65535, `" 443 "`: 443, "4.43e2": 443, "443.0": 443, `"+80"`: 80} {
		got, err := parsePort([]byte(raw))
		if err != nil || got != want {
			t.Fatalf("parsePort(%s) = %d, %v", raw, got, err)
		}
	}
}
