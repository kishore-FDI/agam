package internal

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	httpSwagger "github.com/swaggo/http-swagger"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB, minio *minio.Client, bucketName string, jwtSecret string, cfg *Config) http.Handler {
	r := chi.NewRouter()

	r.Get("/swagger/*", httpSwagger.Handler())

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Public routes - no authentication required
	r.Post("/users", CreateUserHandler(db, cfg))
	r.Post("/users/verify-otp", VerifyUserRegistrationHandler(db))
	r.Post("/auth/login", LoginHandler(db, cfg))
	r.Post("/auth/verify-otp", VerifyOTPHandler(db, jwtSecret))

	// Protected routes - require JWT authentication
	r.Group(func(r chi.Router) {
		r.Use(JWTMiddleware(jwtSecret))

		// Vault routes
		r.Post("/vaults/create", CreateVaultHandler(db))
		// r.Put("/vaults/update", UpdateVaultHandler(db))
		r.Delete("/vaults/delete", DeleteVaultHandler(db))
		r.Get("/vaults", ListVaultsHandler(db))

		r.Get("/thumbnail", GetVaultThumbnail(db,minio))

		// Device routes
		r.Post("/devices/register", RegisterDeviceHandler(db))
		r.Get("/devices/sync", SyncChangesHandler(db))

		// File routes
		r.Post("/files/upload", UploadFileHandler(db, minio))
		r.Delete("/files/delete", DeleteFileHandler(db, minio))
	})

	return r
}
