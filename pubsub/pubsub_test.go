package pubsub

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJSONTime_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		jsonData    string
		expected    time.Time
		expectError bool
	}{
		{
			name:        "Unix timestamp integer",
			jsonData:    "1717545600",
			expected:    time.Unix(1717545600, 0),
			expectError: false,
		},
		{
			name:        "RFC 3339 string",
			jsonData:    `"2024-06-05T00:00:00Z"`,
			expected:    time.Date(2024, 6, 5, 0, 0, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name:        "RFC 3339 string with timezone",
			jsonData:    `"2024-06-05T09:00:00+09:00"`,
			expected:    time.Date(2024, 6, 5, 9, 0, 0, 0, time.FixedZone("JST", 9*60*60)),
			expectError: false,
		},
		{
			name:        "Unix timestamp zero",
			jsonData:    "0",
			expected:    time.Unix(0, 0),
			expectError: false,
		},
		{
			name:        "Negative Unix timestamp",
			jsonData:    "-86400",
			expected:    time.Unix(-86400, 0),
			expectError: false,
		},
		{
			name:        "Invalid string format",
			jsonData:    `"invalid-time-format"`,
			expected:    time.Time{},
			expectError: true,
		},
		{
			name:        "Invalid JSON",
			jsonData:    `{"invalid": "json"}`,
			expected:    time.Time{},
			expectError: true,
		},
		{
			name:        "Boolean value",
			jsonData:    "true",
			expected:    time.Time{},
			expectError: true,
		},
		{
			name:        "Float value",
			jsonData:    "1717545600.5",
			expected:    time.Time{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable (for compatibility with legacy Go versions)
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var jt JSONTime

			err := json.Unmarshal([]byte(tt.jsonData), &jt)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			actualTime := jt.Time
			if !actualTime.Equal(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, actualTime)
			}
		})
	}
}

func TestJSONTime_UnmarshalJSON_InStruct(t *testing.T) {
	t.Parallel()

	// Test unmarshaling JSONTime within a struct
	type TestStruct struct {
		Timestamp JSONTime `json:"timestamp,omitempty"`
		Name      string   `json:"name"`
	}

	tests := []struct {
		name        string
		jsonData    string
		expected    time.Time
		expectError bool
	}{
		{
			name:        "struct with Unix timestamp",
			jsonData:    `{"timestamp": 1717545600, "name": "test"}`,
			expected:    time.Unix(1717545600, 0),
			expectError: false,
		},
		{
			name:        "struct with RFC 3339 string",
			jsonData:    `{"timestamp": "2024-06-05T00:00:00Z", "name": "test"}`,
			expected:    time.Date(2024, 6, 5, 0, 0, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name:        "struct with invalid timestamp",
			jsonData:    `{"timestamp": "invalid", "name": "test"}`,
			expected:    time.Time{},
			expectError: true,
		},
		{
			name:        "struct without timestamp",
			jsonData:    `{"name": "test"}`,
			expected:    time.Time{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable (for compatibility with legacy Go versions)

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var ts TestStruct

			err := json.Unmarshal([]byte(tt.jsonData), &ts)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			actualTime := ts.Timestamp.Time
			if !actualTime.Equal(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, actualTime)
			}

			if ts.Name != "test" {
				t.Errorf("expected name 'test', got %v", ts.Name)
			}
		})
	}
}
