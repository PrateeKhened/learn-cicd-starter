package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "multiple spaces in header",
			headers: http.Header{
				"Authorization": []string{"ApiKey   my-secret-key"},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "empty string as api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "api key with special characters",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc-123_xyz.token"},
			},
			expectedKey:   "abc-123_xyz.token",
			expectedError: nil,
		},
		{
			name: "api key with extra parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey part1 part2 part3"},
			},
			expectedKey:   "part1",
			expectedError: nil,
		},
		{
			name: "empty authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "only whitespace in authorization header",
			headers: http.Header{
				"Authorization": []string{"   "},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "case sensitive prefix",
			headers: http.Header{
				"Authorization": []string{"apikey my-secret-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "nil headers",
			headers:       nil,
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "very long api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey " + string(make([]byte, 1000))},
			},
			expectedKey:   string(make([]byte, 1000)),
			expectedError: nil,
		},
		{
			name: "unicode characters in api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey 🔑key-with-emoji"},
			},
			expectedKey:   "🔑key-with-emoji",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if (err == nil) != (tt.expectedError == nil) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}

			if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error message %q, got %q", tt.expectedError.Error(), err.Error())
			}
		})
	}
}
