package masking

import (
	"strings"
)

// ApplyPartialMask masks part of the data based on type
func ApplyPartialMask(data string, dataType SensitiveDataType) string {
	switch dataType {
	case TypePAN:
		// Show first 2 and last 1: AB****F
		if len(data) >= 10 {
			return data[:2] + strings.Repeat("*", 7) + data[len(data)-1:]
		}
	case TypeAadhaar:
		// Show last 4: **** **** 9012
		cleaned := strings.ReplaceAll(data, " ", "")
		if len(cleaned) >= 12 {
			return "**** **** " + cleaned[len(cleaned)-4:]
		}
	case TypeCreditCard:
		// Show last 4: **** **** **** 1234
		cleaned := strings.ReplaceAll(strings.ReplaceAll(data, " ", ""), "-", "")
		if len(cleaned) >= 4 {
			return "**** **** **** " + cleaned[len(cleaned)-4:]
		}
	case TypeEmail:
		// Show first char and domain: j***@example.com
		parts := strings.Split(data, "@")
		if len(parts) == 2 && len(parts[0]) > 0 {
			return string(parts[0][0]) + "***@" + parts[1]
		}
	case TypePhone:
		// Show last 4: +91 ****** 1234
		cleaned := strings.ReplaceAll(strings.ReplaceAll(data, " ", ""), "-", "")
		if len(cleaned) >= 4 {
			return "****** " + cleaned[len(cleaned)-4:]
		}
	case TypeSSN:
		// Show last 4: ***-**-1234
		if len(data) >= 4 {
			return "***-**-" + data[len(data)-4:]
		}
	}
	return strings.Repeat("*", len(data))
}
