package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"wolfronixgo/internal/database"
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

// API Key Validator
func RequireAPIKey() fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Get("X-Wolfronix-Key")
		if key == "" { return c.Status(401).JSON(fiber.Map{"error": "Missing API Key"}) }

		// Use 'Select' to only fetch ID/Name for speed (Optimization)
		var client database.Client
		err := database.DB.Select("id", "name").Where("api_key = ? AND is_active = ?", key, true).First(&client).Error
		
		if err != nil { return c.Status(403).JSON(fiber.Map{"error": "Invalid API Key"}) }

		c.Locals("client_name", client.Name)
		c.Locals("api_key", key)
		return c.Next()
	}
}
