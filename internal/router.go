package internal

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB, minio *minio.Client) http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Add routes that use db and minio

	return r
}
