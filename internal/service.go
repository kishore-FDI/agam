package internal

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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

func ListVaults(db *gorm.DB, userID uuid.UUID) ([]Vault, error) {
    var vaults []Vault

    // Fetch all vaults belonging to the user
    if err := db.Where("user_id = ?", userID).Find(&vaults).Error; err != nil {
        return nil, fmt.Errorf("failed to fetch vaults: %w", err)
    }

    return vaults, nil
}

func UploadFile(db *gorm.DB, input File) (*File, error) {

	var existing 
}

