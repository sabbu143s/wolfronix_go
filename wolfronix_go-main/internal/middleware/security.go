package middleware

import (
	"time"
	"wolfronixgo/internal/database"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"gorm.io/gorm"
)

func Setup(app *fiber.App) {
	// 1. Helmet (Security Headers)
	app.Use(helmet.New())

	// 2. CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, X-Wolfronix-Key",
	}))
}

// API Key Validator with Quota Enforcement
func RequireAPIKey() fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Get("X-Wolfronix-Key")
		if key == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Missing API Key"})
		}

		// Fetch client with quota fields
		var client database.Client
		err := database.DB.Where("api_key = ? AND is_active = ?", key, true).First(&client).Error

		if err != nil {
			return c.Status(403).JSON(fiber.Map{"error": "Invalid API Key"})
		}

		// Check subscription expiry
		if !client.SubscriptionEnd.IsZero() && client.SubscriptionEnd.Before(time.Now()) {
			return c.Status(403).JSON(fiber.Map{
				"error":      "Subscription expired",
				"expired_at": client.SubscriptionEnd,
				"renew_url":  "https://wolfronix.com/subscription",
			})
		}

		// Check monthly usage reset
		if !client.UsageResetDate.IsZero() && client.UsageResetDate.Before(time.Now()) {
			// Reset usage and set next reset date
			nextReset := time.Now().AddDate(0, 1, 0)
			database.DB.Model(&client).Updates(map[string]interface{}{
				"api_calls_used":   0,
				"usage_reset_date": nextReset,
			})
			client.APICallsUsed = 0
		}

		// Check quota limit (skip for enterprise/unlimited)
		if client.APICallsLimit > 0 && client.APICallsUsed >= client.APICallsLimit {
			return c.Status(429).JSON(fiber.Map{
				"error":       "Monthly API limit exceeded",
				"limit":       client.APICallsLimit,
				"used":        client.APICallsUsed,
				"reset_date":  client.UsageResetDate,
				"upgrade_url": "https://wolfronix.com/subscription",
			})
		}

		// Increment usage counter (async for performance)
		go database.DB.Model(&client).UpdateColumn("api_calls_used", gorm.Expr("api_calls_used + ?", 1))

		c.Locals("client", &client)
		c.Locals("client_name", client.Name)
		c.Locals("api_key", key)
		return c.Next()
	}
}
