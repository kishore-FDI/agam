package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
    "github.com/disintegration/imaging"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"strings"
	"sort"
	"log"

)


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

func UpdateVault(db *gorm.DB, vaultID uuid.UUID, userID int64, updates map[string]interface{}) (*Vault, error) {
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

func DeleteVault(db *gorm.DB, vaultID uuid.UUID, userID int64) error {
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

func ListVaults(db *gorm.DB, userID int64) ([]VaultResponse, error) {
    var vaults []VaultResponse

    // Fetch all vaults belonging to the user
    err := db.
			Model(&Vault{}).
			Select("id", "name", "type", "user_id").
			Where("user_id = ?", userID).
			Scan(&vaults).
			Error
			
	if err != nil {
     return nil, fmt.Errorf("failed to fetch vaults: %w", err)
    }

    return vaults, nil
}

func RegisterDevice(db *gorm.DB, input Device) (*Device, error) {
	// Verify user exists
	var user User
	if err := db.Where("id = ?", input.UserID).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	// Create device
	input.ID = uuid.New()
	input.CreatedTimestamp = time.Now()

	if err := db.Create(&input).Error; err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	return &input, nil
}

func UploadFile(db *gorm.DB, minioClient *minio.Client, input File, fileData []byte, contentType string, deviceID uuid.UUID) (*File, error) {
	
	ctx := context.Background()
	// Verify vault exists
	var vault Vault
	if err := db.Where("id = ?", input.VaultID).First(&vault).Error; err != nil {
		return nil, errors.New("vault not found")
	}
	
	id := uuid.New().String()
	// Generate unique key for MinIO storage
	fileKey  := fmt.Sprintf("files/%s/%s/%s", input.VaultID.String(), id, input.Name)
			
	var currentDevice Device;
	if err := db.Where("id = ?", deviceID).First(&currentDevice).Error; err != nil {
		return nil, errors.New("Device not found")
	}

	// Derive user bucket
	userBucket := fmt.Sprintf("user-%d", currentDevice.UserID)

	// Create bucket if not exists
	exists, err := minioClient.BucketExists(ctx, userBucket)
	if err != nil {
		return nil, fmt.Errorf("failed checking bucket: %w", err)
	}
	if !exists {
		if err := minioClient.MakeBucket(ctx, userBucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("failed creating bucket: %w", err)
		}
	}
	
	// Check if the file is an image
	isImage := strings.HasPrefix(contentType, "image/")
	log.Printf(contentType)
	log.Printf(fmt.Sprintf("%v",isImage))

	var thumbKey string

	if isImage {
		thumbKey = fmt.Sprintf("thumbnails/%s/%s/%s_thumb.jpg", input.VaultID.String(), id, input.Name)

		thumbData, err := generateThumbnail(fileData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate thumbnail: %w", err)
		}

		_, err = minioClient.PutObject(ctx, userBucket, thumbKey, bytes.NewReader(thumbData), int64(len(thumbData)), minio.PutObjectOptions{
			ContentType: "image/jpeg",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to upload thumbnail to MinIO: %w", err)
		}

		input.Thumbnail = thumbKey
	}

	// Upload to MinIO
	_, err = minioClient.PutObject(ctx, userBucket, fileKey, bytes.NewReader(fileData), int64(len(fileData)), minio.PutObjectOptions{
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

	// Save to database
	if err := db.Create(&input).Error; err != nil {
		// Clean up MinIO object if DB insert fails
		minioClient.RemoveObject(ctx, userBucket, fileKey, minio.RemoveObjectOptions{})
		return nil, fmt.Errorf("failed to save file to database: %w", err)
	}

	// Create sync logs for all other devices of the same user (excluding the device that made the change)
	var otherDevices []Device
	if err := db.Where("user_id = ? AND id != ?", currentDevice.UserID, deviceID).Find(&otherDevices).Error; err == nil {
		for _, device := range otherDevices {
			syncLog := SyncLog{
				ID:          uuid.New(),
				VaultID:     input.VaultID,
				FolderID:    input.FolderID,
				FileID:      &input.ID,
				DeviceID:    device.ID,
				Action:      "create",
				LastUpdated: time.Now(),
			}
			db.Create(&syncLog)
		}
	}


	return &input, nil
}

func DeleteFile(db *gorm.DB, minioClient *minio.Client, fileID uuid.UUID, vaultID uuid.UUID, deviceID uuid.UUID) error {
	// Verify file exists and belongs to vault
	var file File
	if err := db.Where("id = ? AND vault_id = ?", fileID, vaultID).First(&file).Error; err != nil {
		return errors.New("file not found or not in this vault")
	}

	// Store file info before deletion for sync log
	folderID := file.FolderID

	var currentDevice Device;
	if err := db.Where("id = ?", deviceID).First(&currentDevice).Error; err != nil {
		return errors.New("Device not found")
	}

	// Derive user bucket
	userBucket := fmt.Sprintf("user-%s", currentDevice.UserID)

	// Delete from MinIO
	ctx := context.Background()
	if err := minioClient.RemoveObject(ctx, userBucket, file.MinioKey, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete file from MinIO: %w", err)
	}

	// Delete thumbnail if exists
	if file.Thumbnail != "" {
		minioClient.RemoveObject(ctx, userBucket, file.Thumbnail, minio.RemoveObjectOptions{})
	}

	// Delete from database
	if err := db.Delete(&file).Error; err != nil {
		return fmt.Errorf("failed to delete file from database: %w", err)
	}


	// Create sync logs for all other devices of the same user (excluding the device that made the change)
	var otherDevices []Device
	if err := db.Where("user_id = ? AND id != ?", currentDevice.UserID, deviceID).Find(&otherDevices).Error; err == nil {
		for _, device := range otherDevices {
			syncLog := SyncLog{
				ID:          uuid.New(),
				VaultID:     vaultID,
				FolderID:    folderID,
				FileID:      &fileID,
				DeviceID:    device.ID,
				Action:      "delete",
				LastUpdated: time.Now(),
			}
			db.Create(&syncLog)
		}
	}

	return nil
}

// SyncLogResponse represents a sync log with file details
type SyncLogResponse struct {
	SyncLog
	File *File `json:"file,omitempty"`
}

func SyncChanges(db *gorm.DB, deviceID uuid.UUID, lastSyncTime *time.Time) ([]SyncLogResponse, error) {
	// Verify device exists
	var device Device
	if err := db.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return nil, errors.New("device not found")
	}

	// Build query for sync logs
	query := db.Where("device_id = ?", deviceID)
	log.Printf(fmt.Sprintf("%v",query))
	
	// If lastSyncTime is provided, only get logs after that time
	if lastSyncTime != nil {
		query = query.Where("last_updated > ?", *lastSyncTime)
		log.Printf(fmt.Sprintf("%v",query))
	}

	// Order by last_updated ascending
	query = query.Order("last_updated ASC")

	var syncLogs []SyncLog
	if err := query.Find(&syncLogs).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch sync logs: %w", err)
	}

	log.Printf(fmt.Sprintf("%v",len(syncLogs)))
	// Build response with file details
	responses := make([]SyncLogResponse, len(syncLogs))
	for i, log := range syncLogs {
		response := SyncLogResponse{SyncLog: log}
		
		// If action is create or update and file_id is set, fetch file details
		if (log.Action == "create" || log.Action == "update") && log.FileID != nil {
			var file File
			if err := db.Where("id = ?", *log.FileID).First(&file).Error; err == nil {
				response.File = &file
			}
		}
		
		responses[i] = response
	}

	return responses, nil
}

func generateThumbnail(data []byte) ([]byte, error) {
    img, err := imaging.Decode(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }

    thumb := imaging.Resize(img, 300, 0, imaging.Lanczos)

    buf := new(bytes.Buffer)
    err = imaging.Encode(buf, thumb, imaging.JPEG)
    if err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

// Service to generate thumbnails for image vaults
func GetThumbnail(db *gorm.DB, minioClient *minio.Client, vaultID uuid.UUID, userID int64) (*ThumbnailResponse, error) {
	var vault Vault

	//Load vault + files
	err := db.
		Preload("Files").
		Where("id = ? AND user_id = ?", vaultID, userID).
		First(&vault).Error
	if err != nil {
		return nil, errors.New("vault not found")
	}

	bucket := fmt.Sprintf("user-%d", userID)

	// Group by date
	dateMap := make(map[string][]Thumbnail)

	for _, f := range vault.Files {
		thumb := Thumbnail{
			FileID: f.ID,
			Name:   f.Name,
		}

		if f.Thumbnail != "" {
			presignedURL, err := minioClient.PresignedGetObject(
				context.Background(),
				bucket,
				f.Thumbnail,
				24*time.Hour,
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate thumbnail URL: %w", err)
			}
			thumb.ThumbnailURL = presignedURL.String()
		}

		day := f.Date.Format("2006-01-02")
		dateMap[day] = append(dateMap[day], thumb)
	}


	// Convert map → []ThumbnailDate (sorted)
	var grouped []ThumbnailDate
	for day, objects := range dateMap {
		parsed, _ := time.Parse("2006-01-02", day)
		grouped = append(grouped, ThumbnailDate{
			Date:    parsed,
			Objects: objects,
		})
	}

	// Sort latest date first
	sort.Slice(grouped, func(i, j int) bool {
		return grouped[i].Date.After(grouped[j].Date)
	})

	return &ThumbnailResponse{
		UserID:     userID,
		VaultID:    vaultID,
		Thumbnails: grouped,
	}, nil
}

