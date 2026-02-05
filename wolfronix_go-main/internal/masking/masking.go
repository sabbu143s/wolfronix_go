package masking

import (
	"regexp"
	"strings"
)

// Compiled regex patterns for sensitive data detection
var (
	// Indian PAN: 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F)
	panRegex = regexp.MustCompile(`[A-Z]{5}[0-9]{4}[A-Z]`)

	// Indian Aadhaar: 12 digits with optional spaces (e.g., 1234 5678 9012)
	aadhaarRegex = regexp.MustCompile(`\d{4}\s?\d{4}\s?\d{4}`)

	// Credit Card: 13-19 digits with optional spaces/dashes
	creditCardRegex = regexp.MustCompile(`\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}`)

	// Email pattern
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

	// Phone (Indian): 10 digits, optional +91 prefix
	phoneRegex = regexp.MustCompile(`(\+91[\s-]?)?[6-9]\d{9}`)

	// SSN (US): XXX-XX-XXXX
	ssnRegex = regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
)

// SensitiveDataType represents the type of sensitive data detected
type SensitiveDataType string

const (
	TypePAN        SensitiveDataType = "PAN"
	TypeAadhaar    SensitiveDataType = "AADHAAR"
	TypeCreditCard SensitiveDataType = "CREDIT_CARD"
	TypeEmail      SensitiveDataType = "EMAIL"
	TypePhone      SensitiveDataType = "PHONE"
	TypeSSN        SensitiveDataType = "SSN"
	TypeUnknown    SensitiveDataType = "UNKNOWN"
)

// DetectedData holds information about detected sensitive data
type DetectedData struct {
	Type     SensitiveDataType
	Value    string
	Position int
}

// DetectSensitiveData scans input and returns all detected sensitive patterns
func DetectSensitiveData(input string) []DetectedData {
	var results []DetectedData

	// Check for PAN
	if matches := panRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			results = append(results, DetectedData{
				Type:     TypePAN,
				Value:    input[m[0]:m[1]],
				Position: m[0],
			})
		}
	}

	// Check for Aadhaar
	if matches := aadhaarRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			results = append(results, DetectedData{
				Type:     TypeAadhaar,
				Value:    input[m[0]:m[1]],
				Position: m[0],
			})
		}
	}

	// Check for Credit Card
	if matches := creditCardRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			val := input[m[0]:m[1]]
			// Validate with Luhn algorithm
			if isValidLuhn(val) {
				results = append(results, DetectedData{
					Type:     TypeCreditCard,
					Value:    val,
					Position: m[0],
				})
			}
		}
	}

	// Check for Email
	if matches := emailRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			results = append(results, DetectedData{
				Type:     TypeEmail,
				Value:    input[m[0]:m[1]],
				Position: m[0],
			})
		}
	}

	// Check for Phone
	if matches := phoneRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			results = append(results, DetectedData{
				Type:     TypePhone,
				Value:    input[m[0]:m[1]],
				Position: m[0],
			})
		}
	}

	// Check for SSN
	if matches := ssnRegex.FindAllStringIndex(input, -1); matches != nil {
		for _, m := range matches {
			results = append(results, DetectedData{
				Type:     TypeSSN,
				Value:    input[m[0]:m[1]],
				Position: m[0],
			})
		}
	}

	return results
}

// isValidLuhn validates a number using Luhn algorithm (credit card checksum)
func isValidLuhn(number string) bool {
	// Remove spaces and dashes
	cleaned := strings.ReplaceAll(strings.ReplaceAll(number, " ", ""), "-", "")

	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(cleaned) - 1; i >= 0; i-- {
		digit := int(cleaned[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

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
