package fakegen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// FakeDataGenerator generates realistic fake data for Layer 1 masking
type FakeDataGenerator struct{}

// NewFakeDataGenerator creates a new fake data generator
func NewFakeDataGenerator() *FakeDataGenerator {
	return &FakeDataGenerator{}
}

// GenerateFakeRecord creates a fake version of a data record
// This is for dev/test environments
func (g *FakeDataGenerator) GenerateFakeRecord(realData map[string]string) map[string]string {
	fake := make(map[string]string)

	for key, value := range realData {
		fake[key] = g.GenerateFakeValue(key, value)
	}

	return fake
}

// GenerateFakeValue generates a fake value based on field name and original value
func (g *FakeDataGenerator) GenerateFakeValue(fieldName, originalValue string) string {
	fieldLower := strings.ToLower(fieldName)

	switch {
	case strings.Contains(fieldLower, "name"):
		return g.FakeName()
	case strings.Contains(fieldLower, "email"):
		return g.FakeEmail()
	case strings.Contains(fieldLower, "phone"):
		return g.FakePhone()
	case strings.Contains(fieldLower, "pan"):
		return g.FakePAN()
	case strings.Contains(fieldLower, "aadhaar"):
		return g.FakeAadhaar()
	case strings.Contains(fieldLower, "card") || strings.Contains(fieldLower, "credit"):
		return g.FakeCreditCard()
	case strings.Contains(fieldLower, "ssn"):
		return g.FakeSSN()
	case strings.Contains(fieldLower, "address"):
		return g.FakeAddress()
	case strings.Contains(fieldLower, "date") || strings.Contains(fieldLower, "dob"):
		return g.FakeDate()
	case strings.Contains(fieldLower, "salary") || strings.Contains(fieldLower, "amount") || strings.Contains(fieldLower, "price"):
		return g.FakeAmount()
	default:
		// For unknown fields, generate similar-length random string
		return g.FakeSimilarString(originalValue)
	}
}

// FakeName generates a fake name
func (g *FakeDataGenerator) FakeName() string {
	firstNames := []string{"John", "Jane", "Alex", "Sam", "Chris", "Pat", "Morgan", "Taylor", "Jordan", "Casey", "Rahul", "Priya", "Amit", "Sneha", "Vikram"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Kumar", "Sharma", "Patel", "Singh", "Gupta", "Shah"}

	return fmt.Sprintf("%s %s", g.randomChoice(firstNames), g.randomChoice(lastNames))
}

// FakeEmail generates a fake email
func (g *FakeDataGenerator) FakeEmail() string {
	domains := []string{"testmail.com", "fakemail.org", "devtest.io", "example.com", "mockdata.net"}
	prefixes := []string{"user", "test", "demo", "fake", "sample", "dev"}

	randNum, _ := rand.Int(rand.Reader, big.NewInt(9999))
	return fmt.Sprintf("%s%d@%s", g.randomChoice(prefixes), randNum.Int64(), g.randomChoice(domains))
}

// FakePhone generates a fake phone number
func (g *FakeDataGenerator) FakePhone() string {
	// Indian format
	prefixes := []string{"91", "98", "99", "88", "87", "70", "89"}
	randNum, _ := rand.Int(rand.Reader, big.NewInt(99999999))
	return fmt.Sprintf("+91 %s%08d", g.randomChoice(prefixes)[:1], randNum.Int64())
}

// FakePAN generates a fake PAN number
func (g *FakeDataGenerator) FakePAN() string {
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var pan strings.Builder

	// First 5 letters
	for i := 0; i < 5; i++ {
		pan.WriteByte(letters[g.randomInt(26)])
	}
	// 4 digits
	randNum, _ := rand.Int(rand.Reader, big.NewInt(9999))
	pan.WriteString(fmt.Sprintf("%04d", randNum.Int64()))
	// Last letter
	pan.WriteByte(letters[g.randomInt(26)])

	return pan.String()
}

// FakeAadhaar generates a fake Aadhaar number
func (g *FakeDataGenerator) FakeAadhaar() string {
	// Format: XXXX XXXX XXXX (12 digits)
	var parts []string
	for i := 0; i < 3; i++ {
		randNum, _ := rand.Int(rand.Reader, big.NewInt(9999))
		parts = append(parts, fmt.Sprintf("%04d", randNum.Int64()))
	}
	return strings.Join(parts, " ")
}

// FakeCreditCard generates a fake credit card number
func (g *FakeDataGenerator) FakeCreditCard() string {
	// Generate a valid-looking (but fake) card number
	// Starting with 4 (Visa-like) for realism
	var card strings.Builder
	card.WriteString("4")

	for i := 0; i < 15; i++ {
		card.WriteString(fmt.Sprintf("%d", g.randomInt(10)))
	}

	// Format with spaces
	cardStr := card.String()
	return fmt.Sprintf("%s %s %s %s", cardStr[0:4], cardStr[4:8], cardStr[8:12], cardStr[12:16])
}

// FakeSSN generates a fake SSN
func (g *FakeDataGenerator) FakeSSN() string {
	area, _ := rand.Int(rand.Reader, big.NewInt(899))
	group, _ := rand.Int(rand.Reader, big.NewInt(99))
	serial, _ := rand.Int(rand.Reader, big.NewInt(9999))

	return fmt.Sprintf("%03d-%02d-%04d", area.Int64()+100, group.Int64()+1, serial.Int64())
}

// FakeAddress generates a fake address
func (g *FakeDataGenerator) FakeAddress() string {
	streets := []string{"Main St", "Oak Ave", "Park Rd", "Test Lane", "Demo Blvd", "Sample Way"}
	cities := []string{"Testville", "Faketown", "Mockburg", "Devland", "Samplecity"}

	num, _ := rand.Int(rand.Reader, big.NewInt(999))
	return fmt.Sprintf("%d %s, %s", num.Int64()+1, g.randomChoice(streets), g.randomChoice(cities))
}

// FakeDate generates a fake date
func (g *FakeDataGenerator) FakeDate() string {
	// Random date between 1950 and 2005
	year := 1950 + g.randomInt(55)
	month := 1 + g.randomInt(12)
	day := 1 + g.randomInt(28)

	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

// FakeAmount generates a fake monetary amount
func (g *FakeDataGenerator) FakeAmount() string {
	amount, _ := rand.Int(rand.Reader, big.NewInt(99999))
	cents, _ := rand.Int(rand.Reader, big.NewInt(99))
	return fmt.Sprintf("%.2f", float64(amount.Int64())+float64(cents.Int64())/100)
}

// FakeSimilarString generates a string of similar length
func (g *FakeDataGenerator) FakeSimilarString(original string) string {
	length := len(original)
	if length == 0 {
		return "FAKE_DATA"
	}

	// Check if it looks like a number
	if matched, _ := regexp.MatchString(`^\d+$`, original); matched {
		return g.randomNumericString(length)
	}

	// Check if it's alphanumeric
	if matched, _ := regexp.MatchString(`^[A-Za-z0-9]+$`, original); matched {
		return g.randomAlphanumericString(length)
	}

	// Default: return a placeholder
	return fmt.Sprintf("FAKE_%s", g.randomAlphanumericString(min(length, 8)))
}

// FakeFileContent generates fake file content for binary files
func (g *FakeDataGenerator) FakeFileContent(originalSize int) []byte {
	// Generate random bytes for fake file
	fakeSize := originalSize
	if fakeSize > 1024*1024 { // Cap at 1MB for dev environment
		fakeSize = 1024 * 1024
	}

	fake := make([]byte, fakeSize)
	rand.Read(fake)

	return fake
}

// FakeFileContentWithMarker generates fake content with a marker indicating it's fake
func (g *FakeDataGenerator) FakeFileContentWithMarker(originalSize int, filename string) []byte {
	marker := fmt.Sprintf("=== WOLFRONIX FAKE DATA ===\nOriginal File: %s\nGenerated: %s\nThis is synthetic test data.\n===========================\n\n",
		filename, time.Now().Format(time.RFC3339))

	markerBytes := []byte(marker)

	// Fill rest with random data
	remainingSize := originalSize - len(markerBytes)
	if remainingSize < 0 {
		remainingSize = 0
	}

	fakeContent := make([]byte, remainingSize)
	rand.Read(fakeContent)

	return append(markerBytes, fakeContent...)
}

// Helper functions

func (g *FakeDataGenerator) randomChoice(choices []string) string {
	idx := g.randomInt(len(choices))
	return choices[idx]
}

func (g *FakeDataGenerator) randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func (g *FakeDataGenerator) randomNumericString(length int) string {
	var result strings.Builder
	for i := 0; i < length; i++ {
		result.WriteString(fmt.Sprintf("%d", g.randomInt(10)))
	}
	return result.String()
}

func (g *FakeDataGenerator) randomAlphanumericString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[g.randomInt(len(charset))]
	}
	return string(result)
}

// GenerateFakeBase64 generates a fake base64 string of similar length
func (g *FakeDataGenerator) GenerateFakeBase64(originalLength int) string {
	// Base64 encodes 3 bytes to 4 chars, so we need ~3/4 of the target length in random bytes
	byteLength := (originalLength * 3) / 4
	if byteLength < 1 {
		byteLength = 1
	}

	randomBytes := make([]byte, byteLength)
	rand.Read(randomBytes)

	return base64.StdEncoding.EncodeToString(randomBytes)[:originalLength]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
