package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Response DTOs with URLs
type FileResponse struct {
	File
	ThumbnailURL string `json:"thumbnail_url,omitempty"`
	ImageURL     string `json:"image_url,omitempty"`
}

type VaultResponse struct {
	Vault
	Files []FileResponse `json:"files"`
}


func CreateUser(db *gorm.DB, input User) (*User, error) {

	// --- Check phone uniqueness ---
	var existing User
	err := db.Where("phone = ?", input.Phone).First(&existing).Error

	if err == nil {
		return nil, errors.New("phone number already in use")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed checking existing user: %w", err)
	}

	// --- Hash password ---
	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Remove plaintext, set hash
	input.Password = string(hashed)
	input.CreatedTimestamp = time.Now()

	// --- Insert into DB ---
	if err := db.Create(&input).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &input, nil
}

func CreateVault(db *gorm.DB, input Vault) (*Vault, error) {
	// --- Validate: user cannot create duplicate vault names ---
	var existing Vault
	err := db.Where("name = ? AND user_id = ?", input.Name, input.UserId).First(&existing).Error

	if err == nil {
		return nil, errors.New("vault with this name already exists for this user")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check existing vault: %w", err)
	}

	// --- Create vault ---
	input.ID = uuid.New()
	input.CreatedTimestamp = time.Now()

	if err := db.Create(&input).Error; err != nil {
		return nil, fmt.Errorf("failed to create vault: %w", err)
	}

	return &input, nil
}

func UpdateVault(db *gorm.DB, vaultID uuid.UUID, userID uuid.UUID, updates map[string]interface{}) (*Vault, error) {
	var vault Vault
	if err := db.Where("id = ? AND user_id = ?", vaultID, userID).First(&vault).Error; err != nil {
		return nil, errors.New("vault not found or not owned by user")
	}

	// If name change requested, ensure uniqueness
	if newName, ok := updates["name"]; ok {
		var temp Vault
		err := db.Where("name = ? AND user_id = ? AND id <> ?", newName, userID, vaultID).First(&temp).Error
		if err == nil {
			return nil, errors.New("another vault with this name already exists")
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed checking name uniqueness: %w", err)
		}
	}

	if err := db.Model(&vault).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update vault: %w", err)
	}

	return &vault, nil
}

func DeleteVault(db *gorm.DB, vaultID uuid.UUID, userID uuid.UUID) error {
	var vault Vault
	err := db.Where("id = ? AND user_id = ?", vaultID, userID).First(&vault).Error
	if err != nil {
		return errors.New("vault not found or not owned by user")
	}

	if err := db.Delete(&vault).Error; err != nil {
		return fmt.Errorf("failed to delete vault: %w", err)
	}

	return nil
}

// GeneratePresignedURL generates a presigned URL for a MinIO object
func GeneratePresignedURL(minioClient *minio.Client, bucketName, objectKey string, expiry time.Duration) (string, error) {
	ctx := context.Background()
	url, err := minioClient.PresignedGetObject(ctx, bucketName, objectKey, expiry, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}
	return url.String(), nil
}

func ListVaults(db *gorm.DB, minioClient *minio.Client, bucketName string, userID uuid.UUID) ([]VaultResponse, error) {
	var vaults []Vault

	// Fetch all vaults belonging to the user with their files
	if err := db.Where("user_id = ?", userID).Preload("Files").Find(&vaults).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch vaults: %w", err)
	}

	// Convert to response format with thumbnail URLs
	vaultResponses := make([]VaultResponse, len(vaults))
	for i, vault := range vaults {
		fileResponses := make([]FileResponse, len(vault.Files))
		for j, file := range vault.Files {
			fileResp := FileResponse{File: file}
			
			// Generate thumbnail URL if thumbnail exists
			if file.Thumbnail != "" {
				thumbnailURL, err := GeneratePresignedURL(minioClient, bucketName, file.Thumbnail, 1*time.Hour)
				if err == nil {
					fileResp.ThumbnailURL = thumbnailURL
				}
			} else {
				// If no thumbnail, use the full image as thumbnail
				thumbnailURL, err := GeneratePresignedURL(minioClient, bucketName, file.MinioKey, 1*time.Hour)
				if err == nil {
					fileResp.ThumbnailURL = thumbnailURL
				}
			}
			
			fileResponses[j] = fileResp
		}
		vaultResponses[i] = VaultResponse{
			Vault: vault,
			Files: fileResponses,
		}
	}

	return vaultResponses, nil
}

func GetVault(db *gorm.DB, minioClient *minio.Client, bucketName string, vaultID uuid.UUID, userID uuid.UUID) (*VaultResponse, error) {
	var vault Vault
	
	// Fetch vault with files, ensuring it belongs to the user
	if err := db.Where("id = ? AND user_id = ?", vaultID, userID).Preload("Files").First(&vault).Error; err != nil {
		return nil, errors.New("vault not found or not owned by user")
	}

	// Convert to response format with thumbnail URLs
	fileResponses := make([]FileResponse, len(vault.Files))
	for i, file := range vault.Files {
		fileResp := FileResponse{File: file}
		
		// Generate thumbnail URL if thumbnail exists
		if file.Thumbnail != "" {
			thumbnailURL, err := GeneratePresignedURL(minioClient, bucketName, file.Thumbnail, 1*time.Hour)
			if err == nil {
				fileResp.ThumbnailURL = thumbnailURL
			}
		} else {
			// If no thumbnail, use the full image as thumbnail
			thumbnailURL, err := GeneratePresignedURL(minioClient, bucketName, file.MinioKey, 1*time.Hour)
			if err == nil {
				fileResp.ThumbnailURL = thumbnailURL
			}
		}
		
		fileResponses[i] = fileResp
	}

	return &VaultResponse{
		Vault: vault,
		Files: fileResponses,
	}, nil
}

func GetFile(db *gorm.DB, minioClient *minio.Client, bucketName string, fileID uuid.UUID, vaultID uuid.UUID) (*FileResponse, error) {
	var file File
	
	// Fetch file, ensuring it belongs to the vault
	if err := db.Where("id = ? AND vault_id = ?", fileID, vaultID).First(&file).Error; err != nil {
		return nil, errors.New("file not found or not in this vault")
	}

	fileResp := FileResponse{File: file}
	
	// Generate full image URL
	imageURL, err := GeneratePresignedURL(minioClient, bucketName, file.MinioKey, 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate image URL: %w", err)
	}
	fileResp.ImageURL = imageURL
	
	// Generate thumbnail URL if thumbnail exists
	if file.Thumbnail != "" {
		thumbnailURL, err := GeneratePresignedURL(minioClient, bucketName, file.Thumbnail, 1*time.Hour)
		if err == nil {
			fileResp.ThumbnailURL = thumbnailURL
		}
	}

	return &fileResp, nil
}

func UploadFile(db *gorm.DB, minioClient *minio.Client, bucketName string, input File, fileData []byte, contentType string) (*File, error) {
	// Generate unique key for MinIO storage
	fileKey := fmt.Sprintf("%s/%s/%s", input.VaultID.String(), uuid.New().String(), input.Name)
	
	// Upload to MinIO
	ctx := context.Background()
	_, err := minioClient.PutObject(ctx, bucketName, fileKey, bytes.NewReader(fileData), int64(len(fileData)), minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload file to MinIO: %w", err)
	}

	// Set file metadata
	input.ID = uuid.New()
	input.MinioKey = fileKey
	input.Time = time.Now()
	input.Date = time.Now()
	input.Size = len(fileData)
	input.Type = contentType

	// Verify vault exists
	var vault Vault
	if err := db.Where("id = ?", input.VaultID).First(&vault).Error; err != nil {
		// If file was uploaded but vault doesn't exist, try to clean up
		minioClient.RemoveObject(ctx, bucketName, fileKey, minio.RemoveObjectOptions{})
		return nil, errors.New("vault not found")
	}

	// Save to database
	if err := db.Create(&input).Error; err != nil {
		// Clean up MinIO object if DB insert fails
		minioClient.RemoveObject(ctx, bucketName, fileKey, minio.RemoveObjectOptions{})
		return nil, fmt.Errorf("failed to save file to database: %w", err)
	}

	return &input, nil
}

func DeleteFile(db *gorm.DB, minioClient *minio.Client, bucketName string, fileID uuid.UUID, vaultID uuid.UUID) error {
	// Verify file exists and belongs to vault
	var file File
	if err := db.Where("id = ? AND vault_id = ?", fileID, vaultID).First(&file).Error; err != nil {
		return errors.New("file not found or not in this vault")
	}

	// Delete from MinIO
	ctx := context.Background()
	if err := minioClient.RemoveObject(ctx, bucketName, file.MinioKey, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete file from MinIO: %w", err)
	}

	// Delete thumbnail if exists
	if file.Thumbnail != "" {
		minioClient.RemoveObject(ctx, bucketName, file.Thumbnail, minio.RemoveObjectOptions{})
	}

	// Delete from database
	if err := db.Delete(&file).Error; err != nil {
		return fmt.Errorf("failed to delete file from database: %w", err)
	}

	return nil
}

