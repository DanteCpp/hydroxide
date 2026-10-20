package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

// Completing the CAPTCHA in the browser must not leave a stdin reader behind:
// the next read belongs to the TOTP or mailbox-password prompt in main.
func TestHumanVerificationPreservesAuthenticationInput(t *testing.T) {
	for _, browserAvailable := range []bool{true, false} {
		name := "browser"
		if !browserAvailable {
			name = "opener-error"
		}
		t.Run(name, func(t *testing.T) {
			stdin, input, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			defer input.Close()
			originalStdin := os.Stdin
			os.Stdin = stdin
			defer func() { os.Stdin = originalStdin }()
			const nextInput = "123456\n"
			if _, err := io.WriteString(input, nextInput); err != nil {
				t.Fatal(err)
			}

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api"+captchaPath || r.URL.Query().Get("Token") != "challenge-token" {
					t.Errorf("unexpected challenge request: %s", r.URL)
				}
				cookie, err := r.Cookie("session")
				if err != nil || cookie.Value != "original-session" {
					t.Error("CAPTCHA request lost the login session cookie")
				}
				http.SetCookie(w, &http.Cookie{Name: "verification", Value: "verified-session", Path: "/"})
				io.WriteString(w, "<html><body>CAPTCHA fixture</body></html>")
			}))
			defer upstream.Close()
			root, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(root, []*http.Cookie{{Name: "session", Value: "original-session", Path: "/"}})
			client := &protonmail.Client{
				RootURL:    upstream.URL + "/api",
				HTTPClient: &http.Client{Jar: jar, Timeout: 3 * time.Second},
			}
			details := &protonmail.HumanVerificationDetails{
				Methods: []string{protonmail.HumanVerificationCaptcha},
				Token:   "challenge-token",
			}
			browser := &http.Client{Timeout: 3 * time.Second}
			var localURL string
			open := func(address string) error {
				localURL = address
				resp, err := browser.Get(address)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), injectedScript) {
					t.Fatal("local challenge did not include the browser completion callback")
				}
				resp, err = browser.Post(address+strings.TrimPrefix(tokenPath, "/"), "text/plain", strings.NewReader("completed-token"))
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Fatalf("completion returned HTTP %d", resp.StatusCode)
				}
				if !browserAvailable {
					return errors.New("no browser installed")
				}
				return nil
			}
			if err := askHumanVerificationWithBrowser(client, details, open); err != nil {
				t.Fatal(err)
			}
			if client.HumanVerification == nil || client.HumanVerification.Token != "completed-token" || client.HumanVerification.Type != protonmail.HumanVerificationCaptcha {
				t.Fatalf("login did not receive the completed CAPTCHA: %+v", client.HumanVerification)
			}
			foundCookie := false
			for _, cookie := range jar.Cookies(root) {
				if cookie.Name == "verification" && cookie.Value == "verified-session" {
					foundCookie = true
				}
			}
			if !foundCookie {
				t.Error("login did not retain the CAPTCHA session cookie")
			}
			if err := stdin.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			code := make([]byte, len(nextInput))
			if _, err := io.ReadFull(stdin, code); err != nil {
				t.Fatalf("next authentication input was consumed by CAPTCHA verification: %v", err)
			}
			if string(code) != nextInput {
				t.Fatalf("next authentication input changed: %q", code)
			}
			browser.CloseIdleConnections()
			if resp, err := browser.Get(localURL); err == nil {
				resp.Body.Close()
				t.Error("local CAPTCHA server is still reachable after verification")
			}
		})
	}
}
