package protonmail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHumanVerificationAPIChallengeAndProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Pm-Human-Verification-Token") == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"Code":9001,"Error":"Complete CAPTCHA","Details":{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"challenge-token"}}`)
			return
		}
		if r.Header.Get("X-Pm-Human-Verification-Token") != "completed-token" || r.Header.Get("X-Pm-Human-Verification-Token-Type") != "captcha" {
			t.Error("request did not carry the completed CAPTCHA proof")
		}
		io.WriteString(w, `{"Code":1000}`)
	}))
	defer server.Close()
	client := &Client{RootURL: server.URL, HTTPClient: server.Client()}
	request, err := client.newRequest(http.MethodPost, "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = client.doJSON(request, nil)
	if err == nil {
		t.Fatal("API challenge was not returned as an error")
	}
	details := HumanVerificationDetailsFromError(fmt.Errorf("login: %w", err))
	if details == nil || details.Token != "challenge-token" || !details.HasMethod(HumanVerificationCaptcha) {
		t.Fatalf("API challenge was lost: %+v", details)
	}
	if details.HasMethod("email") {
		t.Error("challenge reported an unsupported verification method")
	}
	client.HumanVerification = &HumanVerification{Token: "completed-token", Type: HumanVerificationCaptcha}
	request, err = client.newRequest(http.MethodPost, "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.doJSON(request, nil); err != nil {
		t.Fatalf("verified request failed: %v", err)
	}
}

func TestHumanVerificationIgnoresUnrelatedAndIncompleteErrors(t *testing.T) {
	for name, err := range map[string]error{
		"unrelated":     fmt.Errorf("network failure"),
		"missing":       &APIError{Code: CodeHumanVerificationRequired},
		"malformed":     &APIError{Code: CodeHumanVerificationRequired, Details: json.RawMessage(`{`)},
		"missing-token": &APIError{Code: CodeHumanVerificationRequired, Details: json.RawMessage(`{"HumanVerificationMethods":["captcha"]}`)},
		"rejected":      &APIError{Code: CodeHumanVerificationInvalid, Details: json.RawMessage(`{"HumanVerificationToken":"challenge-token"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if details := HumanVerificationDetailsFromError(err); details != nil {
				t.Fatalf("error incorrectly treated as a CAPTCHA challenge: %+v", details)
			}
		})
	}
}
