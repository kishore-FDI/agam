package internal

import (
    "encoding/json"
    "io"
    "net/http"
    "path/filepath"
    "time"

    "github.com/google/uuid"
    "github.com/minio/minio-go/v7"
    "gorm.io/gorm"
)

func CreateUserHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        // Parse incoming JSON body
        var input User
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        // Call service layer
        user, err := CreateUser(db, input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        // Respond with created user (but avoid sending password hash)
        user.Password = "" // never leak hashes

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(user)
    }
}

func CreateVaultHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var input Vault
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        vault, err := CreateVault(db, input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(vault)
    }
}

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

        userID, err := uuid.Parse(userIDStr)
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

        userID, err := uuid.Parse(userIDStr)
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

func ListVaultsHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userIDStr := r.URL.Query().Get("user_id")
        if userIDStr == "" {
            http.Error(w, "user_id is required", http.StatusBadRequest)
            return
        }

        userID, err := uuid.Parse(userIDStr)
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

func UploadFileHandler(db *gorm.DB, minioClient *minio.Client, bucketName string) http.HandlerFunc {
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
            // Try to infer from extension
            ext := filepath.Ext(header.Filename)
            switch ext {
            case ".jpg", ".jpeg":
                contentType = "image/jpeg"
            case ".png":
                contentType = "image/png"
            case ".gif":
                contentType = "image/gif"
            case ".webp":
                contentType = "image/webp"
            default:
                contentType = "application/octet-stream"
            }
        }

        // Validate it's an image
        if !isImageContentType(contentType) {
            http.Error(w, "file must be an image", http.StatusBadRequest)
            return
        }

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
        uploadedFile, err := UploadFile(db, minioClient, bucketName, fileInput, fileData, contentType, deviceID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(uploadedFile)
    }
}

func DeleteFileHandler(db *gorm.DB, minioClient *minio.Client, bucketName string) http.HandlerFunc {
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

        if err := DeleteFile(db, minioClient, bucketName, fileID, vaultID, deviceID); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.WriteHeader(http.StatusNoContent)
    }
}

func RegisterDeviceHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var input Device
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        device, err := RegisterDevice(db, input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(device)
    }
}

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

// LoginRequest represents the login request body
type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// LoginResponse represents the login response
type LoginResponse struct {
    Message string `json:"message"`
    UserID  int64  `json:"user_id"`
}

// VerifyOTPRequest represents the OTP verification request
type VerifyOTPRequest struct {
    UserID int64  `json:"user_id"`
    OTP    string `json:"otp"`
}

// VerifyOTPResponse represents the OTP verification response with JWT token
type VerifyOTPResponse struct {
    Token string `json:"token"`
    UserID int64 `json:"user_id"`
    Email  string `json:"email"`
}

// LoginHandler handles login - validates password and sends OTP
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
        _, err := SendOTP(cfg, user.ID, user.Email)
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

// VerifyOTPHandler handles OTP verification and returns JWT token
func VerifyOTPHandler(db *gorm.DB, jwtSecret string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req VerifyOTPRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        // Verify OTP
        if err := VerifyOTP(req.UserID, req.OTP); err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }

        // Get user details
        var user User
        if err := db.Where("id = ?", req.UserID).First(&user).Error; err != nil {
            http.Error(w, "user not found", http.StatusNotFound)
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
            Email:  user.Email,
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(response)
    }
}
