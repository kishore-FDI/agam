package internal

import (
	"time"

	"github.com/google/uuid"
	
)

// User represents the users table
type User struct {
	ID               int64     `gorm:"primaryKey;"`
	Name             string    `gorm:"type:text;not null"`
	Email            string    `gorm:"type:text;not null"`
	Phone            int       `gorm:"unique;not null"`
	Password         string    `gorm:"type:text;not null"`
	CreatedTimestamp time.Time `gorm:"autoCreateTime"`
}

// Vault represents the vault table
type Vault struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name             string    `gorm:"type:text;not null"`
	Type             string    `gorm:"type:text;not null"`
	CreatedTimestamp time.Time `gorm:"autoCreateTime"`
	UserId			uuid.UUID `gorm:"type:uuid;not null"`

	Files []File `gorm:"constraint:OnDelete:CASCADE;foreignKey:VaultID"`
	Logs  []SyncLog
}

type Folder struct{
	ID 				uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid"`
	Name 			string `gorm:"type:text;not null"`
	Description 	string    `gorm:"type:text;not null"`
	CreatedTimestamp time.Time `gorm:"autoCreateTime"`

	Files []File `gorm:"constraint:OnDelete:CASCADE;foreignKey:VaultID"`
	Logs  []SyncLog

}
// File represents the file table
type File struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	VaultID   uuid.UUID `gorm:"type:uuid;not null;index"`
	Name      string    `gorm:"type:text;not null"`
	Type      string    `gorm:"type:text;not null"`
	Date      time.Time `gorm:"type:date;not null;default:current_date"`
	Time      time.Time `gorm:"type:timestamp;not null;default:now()"`
	Size      int 
	MinioKey  string `gorm:"type:text;not null"`
	Thumbnail string `gorm:"type:text"`

	FolderID   uuid.UUID `gorm:"type:uuid;index"`

	Vault Vault `gorm:"foreignKey:VaultID;constraint:OnDelete:CASCADE"`
	Logs  []SyncLog
}

// SyncLog represents the sync_log table
type SyncLog struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	VaultID  uuid.UUID `gorm:"type:uuid;not null;index"`
	FolderID   uuid.UUID `gorm:"type:uuid"`
	FileID   *uuid.UUID `gorm:"type:uuid;index"`
	Action   string    `gorm:"type:text;not null"`
	Vault    Vault     `gorm:"foreignKey:VaultID;constraint:OnDelete:CASCADE"`
	File     *File     `gorm:"foreignKey:FileID"`
}
