package masking

import "strings"

// LAYER 1: STATIC MASKING (For /dev/test environment)
// Generates a structural "fake" version of data
func GenerateFake(input string) string {
	return "TEST-DATA-" + strings.Repeat("X", len(input)/2)
}

// LAYER 2: DYNAMIC MASKING (Access Control)
// Redacts sensitive info based on user role
func ApplyDynamicMask(data string, role string) string {
	if role == "admin" {
		return data // Admin sees everything
	}
	
	// Example: If data looks like a credit card or email, mask it.
	// Simple implementation: mask middle characters
	if len(data) > 8 {
		return data[:4] + "****REDACTED****" + data[len(data)-4:]
	}
	return "****"
}
