package internal

import (
	"context"
	"log"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func InitMinio(cfg *Config) *minio.Client {
	client, err := minio.New(cfg.MinioURL, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioKey, cfg.MinioSecret, ""),
		Secure: false, // flip to true if using https
	})
	if err != nil {
		log.Fatalf("failed to init minio: %v", err)
	}

	// Ensure bucket exists
	ctx := context.Background()
	exists, _ := client.BucketExists(ctx, cfg.MinioBucket)
	if !exists {
		err = client.MakeBucket(ctx, cfg.MinioBucket, minio.MakeBucketOptions{})
		if err != nil {
			log.Fatalf("failed to create bucket: %v", err)
		}
	}

	return client
}
