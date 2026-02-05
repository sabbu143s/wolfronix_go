package masking

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

func init() {
	gofakeit.Seed(time.Now().UnixNano())
}

// GenerateFakePAN generates a realistic-looking Indian PAN number
// Format: AAAAA0000A (5 letters, 4 digits, 1 letter)
func GenerateFakePAN() string {
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	pan := ""
	// First 5 letters
	for i := 0; i < 5; i++ {
		pan += string(letters[r.Intn(len(letters))])
	}
	// 4 digits
	pan += fmt.Sprintf("%04d", r.Intn(10000))
	// Last letter
	pan += string(letters[r.Intn(len(letters))])

	return pan
}

// GenerateFakeAadhaar generates a realistic-looking Indian Aadhaar number
// Format: XXXX XXXX XXXX (12 digits)
func GenerateFakeAadhaar() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Aadhaar doesn't start with 0 or 1
	first := r.Intn(8) + 2 // 2-9
	return fmt.Sprintf("%d%03d %04d %04d", first, r.Intn(1000), r.Intn(10000), r.Intn(10000))
}

// GenerateFakeCreditCard generates a valid credit card number (passes Luhn)
func GenerateFakeCreditCard() string {
	return gofakeit.CreditCardNumber(nil)
}

// GenerateFakeEmail generates a realistic email address
func GenerateFakeEmail() string {
	return gofakeit.Email()
}

// GenerateFakePhone generates an Indian phone number
func GenerateFakePhone() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Indian mobile numbers start with 6, 7, 8, or 9
	firstDigit := []int{6, 7, 8, 9}[r.Intn(4)]
	return fmt.Sprintf("+91 %d%09d", firstDigit, r.Intn(1000000000))
}

// GenerateFakeSSN generates a US SSN format
func GenerateFakeSSN() string {
	return gofakeit.SSN()
}

// GenerateFakeName generates a realistic name
func GenerateFakeName() string {
	return gofakeit.Name()
}

// GenerateFakeAddress generates a realistic address
func GenerateFakeAddress() string {
	return gofakeit.Address().Address
}

// ReplaceSensitiveWithFake scans input for sensitive data and replaces with fake data
func ReplaceSensitiveWithFake(input string) string {
	result := input

	detected := DetectSensitiveData(input)

	// Process in reverse order to maintain positions
	for i := len(detected) - 1; i >= 0; i-- {
		d := detected[i]
		var fakeData string

		switch d.Type {
		case TypePAN:
			fakeData = GenerateFakePAN()
		case TypeAadhaar:
			fakeData = GenerateFakeAadhaar()
		case TypeCreditCard:
			fakeData = GenerateFakeCreditCard()
		case TypeEmail:
			fakeData = GenerateFakeEmail()
		case TypePhone:
			fakeData = GenerateFakePhone()
		case TypeSSN:
			fakeData = GenerateFakeSSN()
		default:
			continue
		}

		result = result[:d.Position] + fakeData + result[d.Position+len(d.Value):]
	}

	return result
}

// GenerateFakeRecord creates a complete fake record for testing
func GenerateFakeRecord() map[string]string {
	return map[string]string{
		"name":        GenerateFakeName(),
		"email":       GenerateFakeEmail(),
		"phone":       GenerateFakePhone(),
		"pan":         GenerateFakePAN(),
		"aadhaar":     GenerateFakeAadhaar(),
		"credit_card": GenerateFakeCreditCard(),
		"address":     GenerateFakeAddress(),
		"ssn":         GenerateFakeSSN(),
	}
}

// SanitizeForDev replaces all sensitive data with realistic fakes for dev environment
func SanitizeForDev(input string) string {
	return ReplaceSensitiveWithFake(input)
}

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
