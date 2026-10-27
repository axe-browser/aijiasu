package clientapi

import (
	"bytes"
	"encoding/json"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

const (
	maxNodes          = 10000
	maxNodeFieldBytes = 16 << 10
)

// Node contains only fields consumed by the Linux 4.3 list/connect path
// (0x409d2c..0x40a13c and 0x40a6f4..0x40ca3e). Status is display text;
// its availability or entitlement meaning has not been established.
type Node struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Host    string `json:"host"`
	TCPPort int    `json:"tcp_port"`
	UDPPort int    `json:"udp_port"`
}

func parseNodes(raw json.RawMessage) ([]Node, error) {
	raw = bytes.TrimSpace(raw)
	var records []json.RawMessage
	if len(raw) == 0 {
		return nil, ErrInvalidResponse
	}
	switch raw[0] {
	case '[':
		if json.Unmarshal(raw, &records) != nil {
			return nil, ErrInvalidResponse
		}
	case '{':
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return nil, ErrInvalidResponse
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			records = append(records, object[key])
		}
	default:
		return nil, ErrInvalidResponse
	}
	if len(records) > maxNodes {
		return nil, ErrInvalidResponse
	}
	nodes := make([]Node, 0, len(records))
	for _, rawNode := range records {
		var object map[string]json.RawMessage
		if json.Unmarshal(rawNode, &object) != nil || object == nil {
			return nil, ErrInvalidResponse
		}
		var node Node
		for key, target := range map[string]*string{"id": &node.ID, "tit": &node.Title, "sts": &node.Status, "svr": &node.Host} {
			value, err := scalarString(object[key])
			if err != nil || len(value) > maxNodeFieldBytes {
				return nil, ErrInvalidResponse
			}
			*target = value
		}
		fv, err := nestedObject(object["par"], "fv")
		if err != nil {
			return nil, err
		}
		if node.UDPPort, err = parsePort(fv["u"]); err != nil {
			return nil, err
		}
		if node.TCPPort, err = parsePort(fv["p"]); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func nestedObject(raw json.RawMessage, key string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil {
		return nil, ErrInvalidResponse
	}
	inner := outer[key]
	if len(inner) == 0 || bytes.Equal(bytes.TrimSpace(inner), []byte("null")) {
		return nil, nil
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(inner, &result) != nil {
		return nil, ErrInvalidResponse
	}
	return result, nil
}

// Scalar conversions follow the consumed string/null/bool categories. Number
// spelling is retained to avoid introducing floating-point rounding into IDs.
func scalarString(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	if raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", ErrInvalidResponse
		}
		return value, nil
	}
	if bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false")) {
		return string(raw), nil
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil || number == "" {
		return "", ErrInvalidResponse
	}
	return number.String(), nil
}

func parsePort(raw json.RawMessage) (int, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, nil
	}
	value, err := scalarString(raw)
	if err != nil {
		return 0, err
	}
	value = strings.TrimSpace(value)
	// Accept integral JSON numbers, including exponent notation, without float
	// rounding. Numeric strings must be complete decimal integers.
	if raw[0] == '"' {
		port, err := strconv.ParseInt(value, 10, 32)
		if err != nil || port < 0 || port > 65535 {
			return 0, ErrInvalidResponse
		}
		return int(port), nil
	}
	if len(value) > 32 {
		return 0, ErrInvalidResponse
	}
	if exponent := strings.IndexAny(value, "eE"); exponent >= 0 {
		power, err := strconv.Atoi(value[exponent+1:])
		if err != nil || power < -32 || power > 32 {
			return 0, ErrInvalidResponse
		}
	}
	number, ok := new(big.Rat).SetString(value)
	if !ok || !number.IsInt() || number.Sign() < 0 || !number.Num().IsInt64() || number.Num().Int64() > 65535 {
		return 0, ErrInvalidResponse
	}
	return int(number.Num().Int64()), nil
}

func validNodes(nodes []Node) bool {
	if len(nodes) > maxNodes {
		return false
	}
	for _, node := range nodes {
		if len(node.ID) > maxNodeFieldBytes || len(node.Title) > maxNodeFieldBytes || len(node.Status) > maxNodeFieldBytes || len(node.Host) > maxNodeFieldBytes || node.TCPPort < 0 || node.TCPPort > 65535 || node.UDPPort < 0 || node.UDPPort > 65535 {
			return false
		}
	}
	return true
}
