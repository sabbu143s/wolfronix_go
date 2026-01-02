package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"wolfronixgo/internal/config"
	"wolfronixgo/internal/database"
	"wolfronixgo/internal/handlers"
	"wolfronixgo/internal/middleware"
)

func main() {
	// 1. Config & Database
	config.Load()
	database.Connect(config.Global.DBPath)
	database.AutoMigrate()
	
	// 2. RAM Cache Master Keys (Critical for Speed)
	config.InitializeMasterKeys()

	// 3. Fiber App
	app := fiber.New(fiber.Config{
		AppName: "Wolfronix V3.0 (High Perf)",
		DisableStartupMessage: false,
	})

	// 4. Middleware
	middleware.Setup(app)

	// 5. Routes
	
	// Admin (Create Clients)
	app.Post("/admin/clients", handlers.CreateClient)

	// Engine (Protected by API Key)
	api := app.Group("/api/v1", middleware.RequireAPIKey())
	api.Post("/keys", handlers.GenerateKeys)
	api.Post("/encrypt", handlers.EncryptData)
	api.Post("/decrypt", handlers.DecryptData)

	// 6. Start HTTPS
	log.Println("🚀 Wolfronix V3.0 Engine Running on :5001")
	// Make sure you have server.crt and server.key in root folder!
	// For testing without SSL, use app.Listen(":5001")
	if err := app.ListenTLS(":5001", "server.crt", "server.key"); err != nil {
		log.Fatal("Server Error:", err)
	}
}
