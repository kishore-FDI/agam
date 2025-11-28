package internal

import (
	"time"
	"github.com/google/uuid"
)


// Defining the api payloads

type UserInput struct {
	Name     string `json:"name" example:"Alice"`
	Email    string `json:"email" example:"alice@example.com"`
	Phone    int    `json:"phone" example:"9199990000"`
	Password string `json:"password" example:"Secret123!"`
}

type VaultInput struct {
	Name     string 
	Type    string 
	UserID int64
}

type VaultResponse struct {
	ID		uuid.UUID
	Name     string 
	Type    string 
	UserID int64
}

// UserResponse is returned after user creation without nested relations.
type UserResponse struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Email            string    `json:"email"`
	Phone            int       `json:"phone"`
	CreatedTimestamp time.Time `json:"createdTimestamp"`
}

// VerifyUserRegistrationRequest carries the OTP verification payload for registration.
type VerifyUserRegistrationRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type DeviceInput struct{
	Name		string
	UserID		int64
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
	Email string  `json:"email"`
	OTP    string `json:"otp"`
}

// VerifyOTPResponse represents the OTP verification response with JWT token
type VerifyOTPResponse struct {
	Token  string `json:"token"`
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	Name	string
}

// Thumbnail for vaults 
type Thumbnail struct {
	FileID				uuid.UUID
	ThumbnailURL		string
	Name				string
}

type ThumbnailDate struct {
	Date time.Time
	Objects	[]Thumbnail
}

type ThumbnailResponse struct {
	UserID		int64
	VaultID		uuid.UUID
	Thumbnails	[]ThumbnailDate
}

