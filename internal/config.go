package internal

import (
	"os"
)

type Config struct {
	UserName   string
	Password   string
	DBName string
	MinioURL   string
	MinioKey   string
	MinioSecret string
	MinioBucket string
}


func LoadConfig() *Config {
	return &Config{
		UserName:   os.Getenv("DB_USERNAME"),
		Password:   os.Getenv("DB_PASSWORD"),
		DBName: os.Getenv("DB_NAME"),
		MinioURL:   os.Getenv("MINIO_ENDPOINT"),
		MinioKey:   os.Getenv("MINIO_ACCESS_KEY"),
		MinioSecret: os.Getenv("MINIO_SECRET_KEY"),
		MinioBucket: os.Getenv("MINIO_BUCKET"),
	}
}
