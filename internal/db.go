package internal

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)


func InitDB(cfg *Config) *gorm.DB {
	
	// Build DSN (Data Source Name)
	dsn := fmt.Sprintf(
		"host=localhost user=%s password=%s dbname=%s port=5432 sslmode=disable",
		 cfg.UserName, cfg.Password, cfg.DBName,
	)

	// Connect using GORM
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// Auto-migrate all models
	err = db.AutoMigrate(
		&User{},
		&Vault{},
		&File{},
		&Device{},
		&SyncLog{},
	)
	if err != nil {
		log.Fatalf("failed to auto-migrate: %v", err)
	}

	log.Println("Database connection successful and migrated!")

	return db
}
