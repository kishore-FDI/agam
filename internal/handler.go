package internal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"time"
	"strings"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
	"strconv"
	"log"
)

// CreateUserHandler starts the user registration flow by sending an email OTP.
// @Summary Start registration
// @Description Initiates user registration by validating the payload, staging it temporarily, and emailing an OTP. Call /users/verify-otp to finalize creation.
// @Tags users
// @Accept json
// @Produce json
// @Param UserInput body UserInput true "User payload"
// @Success 202 {object} map[string]string
// @Failure 400 {string} string
// @Router /users [post]
func CreateUserHandler(db *gorm.DB, cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Parse incoming JSON body
		var input UserInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		input.Name = strings.TrimSpace(input.Name)
		input.Email = strings.TrimSpace(input.Email)

		if err := validateUserRegistrationInput(input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := ensureUserUniqueness(db, input.Email, input.Phone); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		savePendingUser(input, defaultPendingUserTTL)

		otpKey := registrationOTPKey(input.Email)
		if _, err := SendOTP(cfg, otpKey, input.Email); err != nil {
			http.Error(w, "failed to send OTP: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]string{
			"message": "OTP sent to your email. Verify to complete registration.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}
}

// VerifyUserRegistrationHandler completes registration after OTP validation.
// @Summary Verify registration OTP
// @Description Validates the OTP sent during registration and creates the user record.
// @Tags users
// @Accept json
// @Produce json
// @Param payload body VerifyUserRegistrationRequest true "Verification payload"
// @Success 201 {object} UserResponse
// @Failure 400 {string} string
// @Router /users/verify-otp [post]
func VerifyUserRegistrationHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyUserRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Email == "" || req.OTP == "" {
			http.Error(w, "email and otp are required", http.StatusBadRequest)
			return
		}

		pending, err := getPendingUser(req.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := VerifyOTP(registrationOTPKey(req.Email), req.OTP); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userInput := User{
			Name:     pending.Name,
			Email:    pending.Email,
			Phone:    pending.Phone,
			Password: pending.Password,
		}

		user, err := CreateUser(db, userInput)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		deletePendingUser(req.Email)

		if err := seedDefaultVaults(db, user.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := UserResponse{
			ID:               user.ID,
			Name:             user.Name,
			Email:            user.Email,
			Phone:            user.Phone,
			CreatedTimestamp: user.CreatedTimestamp,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateVaultHandler creates a new vault for the authenticated user.
// @Summary Create vault
// @Tags vaults
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param VaultInput body VaultInput true "Vault payload"
// @Success 201 {object} Vault
// @Failure 400 {string} string
// @Router /vaults/create [post]
func CreateVaultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input VaultInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		inputVault := Vault{
			Name: input.Name,
			Type: input.Type,
			UserId : input.UserID,
		}
		vault, err := CreateVault(db, inputVault)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(vault)
	}
}

// UpdateVaultHandler updates vault metadata.
// @Summary Update vault
// @Tags vaults
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param vault_id query string true "Vault ID"
// @Param user_id query string true "Owner user ID"
// @Param updates body object true "Fields to update"
// @Success 200 {object} Vault
// @Failure 400 {string} string
// @Router /vaults/update [put]
func UpdateVaultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Expect: /vaults/{vaultID}?user={userID}
		vaultIDStr := r.URL.Query().Get("vault_id")
		userIDStr := r.URL.Query().Get("user_id")

		if vaultIDStr == "" || userIDStr == "" {
			http.Error(w, "vault_id and user_id are required", http.StatusBadRequest)
			return
		}

		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			http.Error(w, "invalid vault_id", http.StatusBadRequest)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid user_id", http.StatusBadRequest)
			return
		}

		// Parse JSON body for updates
		updates := map[string]interface{}{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		updatedVault, err := UpdateVault(db, vaultID, userID, updates)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedVault)
	}
}

// DeleteVaultHandler removes an existing vault.
// @Summary Delete vault
// @Tags vaults
// @Security BearerAuth
// @Param vault_id query string true "Vault ID"
// @Param user_id query string true "Owner user ID"
// @Success 204 "No Content"
// @Failure 400 {string} string
// @Router /vaults/delete [delete]
func DeleteVaultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vaultIDStr := r.URL.Query().Get("vault_id")
		userIDStr := r.URL.Query().Get("user_id")

		if vaultIDStr == "" || userIDStr == "" {
			http.Error(w, "vault_id and user_id are required", http.StatusBadRequest)
			return
		}

		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			http.Error(w, "invalid vault_id", http.StatusBadRequest)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid user_id", http.StatusBadRequest)
			return
		}

		if err := DeleteVault(db, vaultID, userID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ListVaultsHandler lists all vaults for a user.
// @Summary List vaults
// @Tags vaults
// @Security BearerAuth
// @Produce json
// @Param user_id query string true "Owner user ID"
// @Success 200 {array} VaultInput
// @Failure 400 {string} string
// @Router /vaults [get]
func ListVaultsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userIDStr := r.URL.Query().Get("user_id")
		if userIDStr == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid user_id", http.StatusBadRequest)
			return
		}

		vaults, err := ListVaults(db, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vaults)
	}
}

// Thumbnail lists all thumbnails for a vault.
// @Summary List vaults
// @Tags vaults
// @Security BearerAuth
// @Produce json
// @Param userId query string true "Owner user ID"
// @Param vaultId query string true "Vault ID"
// @Success 200 {array} VaultInput
// @Failure 400 {string} string
// @Router /thumbnail [get]
func GetVaultThumbnail(db *gorm.DB, minioClient *minio.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		
		userIDStr := r.URL.Query().Get("userId")

		if userIDStr == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)

		if err != nil {
			http.Error(w, "invalid user_id", http.StatusBadRequest)
			return
		}

		vaultIDStr := r.URL.Query().Get("vaultId")
        if vaultIDStr == "" {
            http.Error(w, "vault_id is required", http.StatusBadRequest)
            return
        }

        vaultID, err := uuid.Parse(vaultIDStr)
        if err != nil {
            log.Printf("%v", err)
            http.Error(w, "invalid vault_id", http.StatusBadRequest)
            return
        }


		thumbnail, err := GetThumbnail(db, minioClient, vaultID, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(thumbnail)
	}
}

// UploadFileHandler uploads an image into a vault.
// @Summary Upload file
// @Tags files
// @Security BearerAuth
// @Accept mpfd
// @Produce json
// @Param file formData file true "Image file"
// @Param vault_id formData string true "Vault ID"
// @Param folder_id formData string false "Folder ID"
// @Param device_id formData string true "Device ID"
// @Success 201 {object} File
// @Failure 400 {string} string
// @Router /files/upload [post]
func UploadFileHandler(db *gorm.DB, minioClient *minio.Client ) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse multipart form (max 32MB)
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			http.Error(w, "failed to parse multipart form", http.StatusBadRequest)
			return
		}

		// Get file from form
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file is required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Get vault_id from form
		vaultIDStr := r.FormValue("vault_id")
		if vaultIDStr == "" {
			http.Error(w, "vault_id is required", http.StatusBadRequest)
			return
		}

		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			http.Error(w, "invalid vault_id", http.StatusBadRequest)
			return
		}

		// Get optional folder_id
		var folderID *uuid.UUID
		if folderIDStr := r.FormValue("folder_id"); folderIDStr != "" {
			parsed, err := uuid.Parse(folderIDStr)
			if err != nil {
				http.Error(w, "invalid folder_id", http.StatusBadRequest)
				return
			}
			folderID = &parsed
		}

		// Get device_id (required)
		deviceIDStr := r.FormValue("device_id")
		if deviceIDStr == "" {
			http.Error(w, "device_id is required", http.StatusBadRequest)
			return
		}

		deviceID, err := uuid.Parse(deviceIDStr)
		if err != nil {
			http.Error(w, "invalid device_id", http.StatusBadRequest)
			return
		}

		// Read file data
		fileData, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "failed to read file", http.StatusInternalServerError)
			return
		}

		// Determine content type
		contentType := header.Header.Get("Content-Type")
		if contentType == "" {
			ext := strings.ToLower(filepath.Ext(header.Filename))

			switch ext {
			case ".jpg", ".jpeg":
				contentType = "image/jpeg"
			case ".png":
				contentType = "image/png"
			case ".gif":
				contentType = "image/gif"
			case ".webp":
				contentType = "image/webp"

			case ".pdf":
				contentType = "application/pdf"
			case ".doc":
				contentType = "application/msword"
			case ".docx":
				contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
			case ".xls":
				contentType = "application/vnd.ms-excel"
			case ".xlsx":
				contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

			case ".md":
				contentType = "text/markdown"

			default:
				contentType = "application/octet-stream"
			}
		}


		// Validate it's an image
		// if !isImageContentType(contentType) {
		// 	http.Error(w, "file must be an image", http.StatusBadRequest)
		// 	return
		// }

		// Create file input
		fileInput := File{
			VaultID:  vaultID,
			Name:     header.Filename,
			FolderID: uuid.Nil,
		}
		if folderID != nil {
			fileInput.FolderID = *folderID
		}

		// Upload file
		uploadedFile, err := UploadFile(db, minioClient, fileInput, fileData, contentType, deviceID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(uploadedFile)
	}
}

// DeleteFileHandler removes a file from storage.
// @Summary Delete file
// @Tags files
// @Security BearerAuth
// @Param file_id query string true "File ID"
// @Param vault_id query string true "Vault ID"
// @Param device_id query string true "Device ID"
// @Success 204 "No Content"
// @Failure 400 {string} string
// @Router /files/delete [delete]
func DeleteFileHandler(db *gorm.DB, minioClient *minio.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileIDStr := r.URL.Query().Get("file_id")
		vaultIDStr := r.URL.Query().Get("vault_id")
		deviceIDStr := r.URL.Query().Get("device_id")

		if fileIDStr == "" || vaultIDStr == "" || deviceIDStr == "" {
			http.Error(w, "file_id, vault_id, and device_id are required", http.StatusBadRequest)
			return
		}

		fileID, err := uuid.Parse(fileIDStr)
		if err != nil {
			http.Error(w, "invalid file_id", http.StatusBadRequest)
			return
		}

		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			http.Error(w, "invalid vault_id", http.StatusBadRequest)
			return
		}

		deviceID, err := uuid.Parse(deviceIDStr)
		if err != nil {
			http.Error(w, "invalid device_id", http.StatusBadRequest)
			return
		}

		if err := DeleteFile(db, minioClient, fileID, vaultID, deviceID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// RegisterDeviceHandler registers a new device for sync.
// @Summary Register device
// @Tags devices
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param DeviceInput body DeviceInput true "Device payload"
// @Success 201 {object} Device
// @Failure 400 {string} string
// @Router /devices/register [post]
func RegisterDeviceHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input DeviceInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		deviceInput := Device{
			Name: input.Name,
			UserID: input.UserID,
		}

		device, err := RegisterDevice(db, deviceInput)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(device)
	}
}

// SyncChangesHandler returns sync logs for a device.
// @Summary Sync changes
// @Tags devices
// @Security BearerAuth
// @Produce json
// @Param device_id query string true "Device ID"
// @Param last_sync_time query string false "RFC3339 timestamp"
// @Success 200 {array} SyncLog
// @Failure 400 {string} string
// @Router /devices/sync [get]
func SyncChangesHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceIDStr := r.URL.Query().Get("device_id")
		if deviceIDStr == "" {
			http.Error(w, "device_id is required", http.StatusBadRequest)
			return
		}

		deviceID, err := uuid.Parse(deviceIDStr)
		if err != nil {
			http.Error(w, "invalid device_id", http.StatusBadRequest)
			return
		}

		// Optional last_sync_time parameter (RFC3339 format)
		var lastSyncTime *time.Time
		if lastSyncStr := r.URL.Query().Get("last_sync_time"); lastSyncStr != "" {
			parsed, err := time.Parse(time.RFC3339, lastSyncStr)
			if err != nil {
				http.Error(w, "invalid last_sync_time format (use RFC3339)", http.StatusBadRequest)
				return
			}
			lastSyncTime = &parsed
		}

		changes, err := SyncChanges(db, deviceID, lastSyncTime)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(changes)
	}
}

func isImageContentType(contentType string) bool {
	imageTypes := []string{
		"image/jpeg",
		"image/jpg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/bmp",
		"image/svg+xml",
	}
	for _, imgType := range imageTypes {
		if contentType == imgType {
			return true
		}
	}
	return false
}

// LoginHandler starts the password + OTP login flow.
// @Summary Initiate login
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body LoginRequest true "Login payload"
// @Success 200 {object} LoginResponse
// @Failure 400 {string} string
// @Router /auth/login [post]
func LoginHandler(db *gorm.DB, cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		// Find user by email
		var user User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}

		// Validate password
		if err := ValidatePassword(user.Password, req.Password); err != nil {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}

		// Send OTP
		_, err := SendOTP(cfg, userOTPKey(user.ID), user.Email)
		if err != nil {
			http.Error(w, "failed to send OTP: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		response := LoginResponse{
			Message: "OTP sent to your email address",
			UserID:  user.ID,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// VerifyOTPHandler validates OTP and issues a JWT.
// @Summary Verify OTP
// @Tags auth
// @Accept json
// @Produce json
// @Param payload body VerifyOTPRequest true "OTP payload"
// @Success 200 {object} VerifyOTPResponse
// @Failure 400 {string} string
// @Router /auth/verify-otp [post]
func VerifyOTPHandler(db *gorm.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyOTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		
		var user User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			http.Error(w, "invalid email", http.StatusUnauthorized)
			return
		}


		// Verify OTP
		if err := VerifyOTP(userOTPKey(user.ID), req.OTP); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Generate JWT token
		token, err := GenerateJWT(user.ID, user.Email, jwtSecret)
		if err != nil {
			http.Error(w, "failed to generate token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return token
		response := VerifyOTPResponse{
			Token:  token,
			UserID: user.ID,
			Name: user.Name,
			Email:  user.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

func validateUserRegistrationInput(input UserInput) error {
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(input.Email) == "" {
		return errors.New("email is required")
	}
	if input.Phone == 0 {
		return errors.New("phone is required")
	}
	if strings.TrimSpace(input.Password) == "" {
		return errors.New("password is required")
	}
	return nil
}

func ensureUserUniqueness(db *gorm.DB, email string, phone int) error {
	var existing User
	if err := db.Where("email = ?", email).First(&existing).Error; err == nil {
		return errors.New("email already registered")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	if phone != 0 {
		if err := db.Where("phone = ?", phone).First(&existing).Error; err == nil {
			return errors.New("phone number already registered")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}

	return nil
}

func seedDefaultVaults(db *gorm.DB, userID int64) error {
	vaults := []Vault{
		{
			Name:   "Memories",
			Type:   "images",
			UserId: userID,
		},
		{
			Name:   "Thoughts",
			Type:   "texts",
			UserId: userID,
		},
		{
			Name:   "Echoes",
			Type:   "audios",
			UserId: userID,
		},
		{
			Name:   "Documents",
			Type:   "documents",
			UserId: userID,
		},
	}

	for _, v := range vaults {
		if _, err := CreateVault(db, v); err != nil {
			return err
		}
	}

	return nil
}
