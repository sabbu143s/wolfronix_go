package masking

// Role represents user access levels
type Role string

const (
	RoleOwner   Role = "owner"   // Full access - sees everything
	RoleAdmin   Role = "admin"   // Full access - sees everything
	RoleAnalyst Role = "analyst" // Partial access - sees masked data
	RoleSupport Role = "support" // Limited access - sees partially masked
	RoleGuest   Role = "guest"   // Minimal access - fully masked
)

// MaskingLevel defines how much to reveal
type MaskingLevel int

const (
	MaskNone    MaskingLevel = iota // Show everything
	MaskPartial                     // Show first/last chars
	MaskFull                        // Show only ****
)

// RoleMaskingConfig defines masking rules per role per data type
var RoleMaskingConfig = map[Role]map[SensitiveDataType]MaskingLevel{
	RoleOwner: {
		TypePAN:        MaskNone,
		TypeAadhaar:    MaskNone,
		TypeCreditCard: MaskNone,
		TypeEmail:      MaskNone,
		TypePhone:      MaskNone,
		TypeSSN:        MaskNone,
	},
	RoleAdmin: {
		TypePAN:        MaskNone,
		TypeAadhaar:    MaskNone,
		TypeCreditCard: MaskNone,
		TypeEmail:      MaskNone,
		TypePhone:      MaskNone,
		TypeSSN:        MaskNone,
	},
	RoleAnalyst: {
		TypePAN:        MaskFull,    // Cannot see PAN
		TypeAadhaar:    MaskFull,    // Cannot see Aadhaar
		TypeCreditCard: MaskPartial, // Last 4 digits
		TypeEmail:      MaskPartial, // j***@domain.com
		TypePhone:      MaskPartial, // Last 4 digits
		TypeSSN:        MaskFull,    // Cannot see SSN
	},
	RoleSupport: {
		TypePAN:        MaskPartial, // First 2, last 1
		TypeAadhaar:    MaskPartial, // Last 4
		TypeCreditCard: MaskPartial, // Last 4
		TypeEmail:      MaskPartial, // j***@domain.com
		TypePhone:      MaskPartial, // Last 4
		TypeSSN:        MaskPartial, // Last 4
	},
	RoleGuest: {
		TypePAN:        MaskFull,
		TypeAadhaar:    MaskFull,
		TypeCreditCard: MaskFull,
		TypeEmail:      MaskFull,
		TypePhone:      MaskFull,
		TypeSSN:        MaskFull,
	},
}

// ApplyRoleMask applies masking based on user role (RBAC Layer 2)
func ApplyRoleMask(data string, dataType SensitiveDataType, role Role) string {
	config, exists := RoleMaskingConfig[role]
	if !exists {
		// Default to guest (most restrictive) if role unknown
		config = RoleMaskingConfig[RoleGuest]
	}

	level, exists := config[dataType]
	if !exists {
		level = MaskFull // Default to full mask for unknown types
	}

	switch level {
	case MaskNone:
		return data
	case MaskPartial:
		return ApplyPartialMask(data, dataType)
	case MaskFull:
		return MaskFully(data)
	default:
		return MaskFully(data)
	}
}

// MaskFully replaces all characters with asterisks
func MaskFully(data string) string {
	return "**********"
}

// ApplyRoleMaskToRecord masks all sensitive fields in a record based on role
func ApplyRoleMaskToRecord(record map[string]string, role Role) map[string]string {
	result := make(map[string]string)

	fieldTypeMapping := map[string]SensitiveDataType{
		"pan":         TypePAN,
		"aadhaar":     TypeAadhaar,
		"credit_card": TypeCreditCard,
		"email":       TypeEmail,
		"phone":       TypePhone,
		"ssn":         TypeSSN,
	}

	for key, value := range record {
		if dataType, isSensitive := fieldTypeMapping[key]; isSensitive {
			result[key] = ApplyRoleMask(value, dataType, role)
		} else {
			result[key] = value // Non-sensitive fields pass through
		}
	}

	return result
}

// MaskAllSensitiveInText scans text and masks all detected sensitive data
func MaskAllSensitiveInText(input string, role Role) string {
	result := input
	detected := DetectSensitiveData(input)

	// Process in reverse order to maintain positions
	for i := len(detected) - 1; i >= 0; i-- {
		d := detected[i]
		masked := ApplyRoleMask(d.Value, d.Type, role)
		result = result[:d.Position] + masked + result[d.Position+len(d.Value):]
	}

	return result
}
