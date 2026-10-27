package clientapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	maxSessionFieldBytes = 64 << 10
	maxSyncSections      = 256
	maxSyncKeyBytes      = 128
)

// Refresh uses the normal 4.3 login synchronization command with a cached token.
// Its section versions are encoded by 0x44496a..0x444b42 as _sync[section].
// The supplied session is never mutated, including on failed synchronization.
func (client *Client) Refresh(ctx context.Context, prior Session) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, safeRequestError(ctx, err)
	}
	if !validAccount(prior.Username) || strings.TrimSpace(prior.LoginToken) == "" || len(prior.LoginToken) > maxSessionFieldBytes {
		return Session{}, errors.New("refresh requires a valid session username and login token")
	}
	if err := validateSyncVersion(prior.SyncVersion); err != nil {
		return Session{}, errors.New("session has invalid synchronization versions")
	}
	if !validNodes(prior.Nodes) || len(prior.ServiceUsername) > maxSessionFieldBytes {
		return Session{}, errors.New("session exceeds synchronization resource limits")
	}
	parameters := map[string]string{"username": prior.Username, "_client_login": prior.LoginToken}
	for section, version := range prior.SyncVersion {
		parameters["_sync["+section+"]"] = version
	}
	data, err := client.postAuthenticated(ctx, parameters)
	if err != nil {
		return Session{}, err
	}
	return parseSyncResponse(data, prior.Username, &prior)
}

func validAccount(username string) bool {
	return strings.TrimSpace(username) != "" && len(username) <= maxSessionFieldBytes && !strings.ContainsAny(username, "\r\n\x00")
}

func parseLoginResponse(data []byte, username string) (Session, error) {
	return parseSyncResponse(data, username, nil)
}

func parseSyncResponse(data []byte, username string, prior *Session) (Session, error) {
	// Exact-case maps avoid accepting similarly named authentication fields.
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || root == nil {
		return Session{}, ErrInvalidResponse
	}
	versions, err := parseSyncVersion(root["SyncVersion"])
	if err != nil {
		return Session{}, err
	}
	for section := range versions {
		if strings.HasPrefix(section, "Debug.") {
			continue
		}
		_, present := root[section]
		unchanged := prior != nil && sameVersion(prior.SyncVersion, versions, section)
		if !present && !unchanged {
			return Session{}, fmt.Errorf("%w: changed synchronization section is missing", ErrInvalidResponse)
		}
	}
	var session Session
	if raw, exists := root["Login"]; exists {
		session, err = parseLoginSection(raw, username)
		if err != nil {
			return Session{}, err
		}
	} else if prior == nil || !sameVersion(prior.SyncVersion, versions, "Login") {
		return Session{}, fmt.Errorf("%w: login section is missing", ErrInvalidResponse)
	}
	if prior != nil && sameVersion(prior.SyncVersion, versions, "Login") {
		session = *prior
	}
	session.SyncVersion = versions
	if raw, present := root["Servers"]; present {
		session.Nodes, err = parseNodes(raw)
		if err != nil {
			return Session{}, err
		}
	} else if prior != nil && (prior.Nodes != nil || hasVersion(prior.SyncVersion, "Servers")) && !sameVersion(prior.SyncVersion, versions, "Servers") {
		return Session{}, fmt.Errorf("%w: servers section is missing", ErrInvalidResponse)
	}
	if prior != nil && sameVersion(prior.SyncVersion, versions, "Servers") {
		session.Nodes = slices.Clone(prior.Nodes)
		if session.Nodes == nil {
			// Older cached empty lists were omitted despite a Servers version.
			session.Nodes = []Node{}
		}
	}
	// When Login changed or Servers were absent, no slices/maps from prior may
	// escape by aliasing. Callers can safely persist or edit the result.
	session.Nodes = slices.Clone(session.Nodes)
	return session, nil
}

func parseLoginSection(raw json.RawMessage, username string) (Session, error) {
	var login map[string]json.RawMessage
	if json.Unmarshal(raw, &login) != nil || login == nil {
		return Session{}, ErrInvalidResponse
	}
	var result string
	if json.Unmarshal(login["AuthResult"], &result) != nil || result == "" {
		return Session{}, ErrInvalidResponse
	}
	if result != "OK" {
		return Session{}, ErrAuthRejected
	}
	var token string
	if json.Unmarshal(login["LoginToken"], &token) != nil || strings.TrimSpace(token) == "" || len(token) > maxSessionFieldBytes {
		return Session{}, fmt.Errorf("%w: successful login response is missing a nonempty login token", ErrInvalidResponse)
	}
	var expires json.Number
	if raw, exists := login["ExpireTime"]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if json.Unmarshal(raw, &expires) != nil || expires == "" {
			return Session{}, fmt.Errorf("%w: invalid expiry time", ErrInvalidResponse)
		}
	}
	serviceUsername, err := scalarString(login["UserName"])
	if err != nil || len(serviceUsername) > maxSessionFieldBytes {
		return Session{}, ErrInvalidResponse
	}
	return Session{Username: username, LoginToken: token, AuthenticatedAt: time.Now().UTC(), ExpireTime: expires, ServiceUsername: serviceUsername}, nil
}

func parseSyncVersion(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil || len(object) > maxSyncSections {
		return nil, ErrInvalidResponse
	}
	versions := make(map[string]string, len(object))
	for key, raw := range object {
		value, err := scalarString(raw)
		if err != nil {
			return nil, ErrInvalidResponse
		}
		versions[key] = value
	}
	if validateSyncVersion(versions) != nil {
		return nil, ErrInvalidResponse
	}
	return versions, nil
}

func validateSyncVersion(versions map[string]string) error {
	if len(versions) > maxSyncSections {
		return ErrInvalidResponse
	}
	for key, value := range versions {
		if key == "" || len(key) > maxSyncKeyBytes || strings.ContainsAny(key, "[]&=\r\n\x00") || len(value) > maxNodeFieldBytes {
			return ErrInvalidResponse
		}
	}
	return nil
}

func sameVersion(old, current map[string]string, section string) bool {
	previous, exists := old[section]
	value, present := current[section]
	return exists && present && previous == value
}

func hasVersion(versions map[string]string, section string) bool {
	_, exists := versions[section]
	return exists
}
