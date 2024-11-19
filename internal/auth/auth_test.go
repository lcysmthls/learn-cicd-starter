package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("No Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Errorf("Expected error, got nil")
		}
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty API key, got %s", apiKey)
		}
	})

	t.Run("Malformed Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer invalidkey")
		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Errorf("Expected error, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty API key, got %s", apiKey)
		}
	})

	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey validapikey123")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if apiKey != "validapikey123" {
			t.Errorf("Expected API key 'validapikey123', got %s", apiKey)
		}
	})
}
