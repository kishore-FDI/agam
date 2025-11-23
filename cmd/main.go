package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/venkataramanakb/agam/internal"
)

func main() {
	godotenv.Load()

	cfg := internal.LoadConfig()

	db := internal.InitDB(cfg)
	minioClient := internal.InitMinio(cfg)

	// Ensure JWT secret is set
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	r := internal.SetupRouter(db, minioClient, cfg.MinioBucket, cfg.JWTSecret, cfg)

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", r)
}
