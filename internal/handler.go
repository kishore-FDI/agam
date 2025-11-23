package internal

import (
    "encoding/json"
    "io"
    "net/http"
    "path/filepath"

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
        uploadedFile, err := UploadFile(db, minioClient, bucketName, fileInput, fileData, contentType)
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

        if fileIDStr == "" || vaultIDStr == "" {
            http.Error(w, "file_id and vault_id are required", http.StatusBadRequest)
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

        if err := DeleteFile(db, minioClient, bucketName, fileID, vaultID); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.WriteHeader(http.StatusNoContent)
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
