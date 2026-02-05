package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v2"
	"wolfronixgo/internal/database"
)

func CreateClient(c *fiber.Ctx) error {
	var req struct { Name string `json:"name"` }
	if err := c.BodyParser(&req); err != nil { return c.SendStatus(400) }

	// Generate Random API Key
	bytes := make([]byte, 24)
	rand.Read(bytes)
	apiKey := hex.EncodeToString(bytes)

	client := database.Client{
		Name:      req.Name,
		APIKey:    apiKey,
		IsActive:  true,
		CreatedAt: time.Now(),
	}
	database.DB.Create(&client)

	return c.JSON(client)
}
