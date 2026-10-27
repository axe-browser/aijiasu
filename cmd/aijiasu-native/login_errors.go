package main

import (
	"encoding/json"
	"io"

	"aijiasu-native/internal/native/clientapi"
)

type loginErrorOutput struct {
	writer     io.Writer
	format     string
	diagnostic clientapi.LoginDiagnostic
}

type loginErrorDetail struct {
	Code       string `json:"code"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func (output *loginErrorOutput) Write(data []byte) (int, error) {
	if output.format == "json" {
		return len(data), nil
	}
	return output.writer.Write(data)
}

func (output *loginErrorOutput) finish(exitCode int) {
	if output.format != "json" || exitCode == 0 {
		return
	}
	code := output.diagnostic.Code
	if code == "" {
		code = "unknown"
	}
	if exitCode == exitCancelled {
		code = "canceled"
	}
	detail := loginErrorDetail{Code: code}
	if code == "http_status" {
		detail.HTTPStatus = output.diagnostic.HTTPStatus
	}
	json.NewEncoder(output.writer).Encode(struct {
		SchemaVersion int              `json:"schemaVersion"`
		Command       string           `json:"command"`
		Error         loginErrorDetail `json:"error"`
	}{1, "login", detail})
}
