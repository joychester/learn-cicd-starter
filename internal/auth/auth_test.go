// auth_test.go
package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyValidHeader(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey abcdef123456")

	key, err := GetAPIKey(headers)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	expectedKey := "abcdef123456"
	if key != expectedKey {
		t.Errorf("Expected API key to be %s, but got: %s", expectedKey, key)
	}
}

func TestGetAPIKeyNoHeader(t *testing.T) {
	headers := make(http.Header)

	key, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error 'ErrNoAuthHeaderIncluded', but got: %v", err)
	}

	if key != "" {
		t.Errorf("Expected empty API key, but got: %s", key)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer xyz")

	key, err := GetAPIKey(headers)

	expectedError := "malformed authorization header"
	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected error '%s', but got: %v", expectedError, err)
	}

	if key != "" {
		t.Errorf("Expected empty API key, but got: %s", key)
	}
}
