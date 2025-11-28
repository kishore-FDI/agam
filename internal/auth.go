package internal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/smtp"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// otpStore stores OTPs in memory with expiration
type otpStore struct {
	mu   sync.RWMutex
	otps map[string]otpEntry
}

type otpEntry struct {
	code      string
	expiresAt time.Time
}

var globalOTPStore = &otpStore{
	otps: make(map[string]otpEntry),
}

// cleanupExpiredOTPs removes expired OTPs from memory
func (s *otpStore) cleanupExpiredOTPs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	for key, entry := range s.otps {
		if now.After(entry.expiresAt) {
			delete(s.otps, key)
		}
	}
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateJWT generates a JWT token for a user
func GenerateJWT(userID int64, email string, jwtSecret string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Token expires in 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(tokenString string, jwtSecret string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidatePassword validates a password against a hash
func ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateOTP generates a 6-digit OTP
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SendEmail sends an email using SMTP
func SendEmail(cfg *Config, to, subject, body string) error {
	// If SMTP is not configured, just log the email (for development)
	if cfg.SMTPHost == "" || cfg.SMTPPort == "" {
		fmt.Printf("Email would be sent to: %s\nSubject: %s\nBody: %s\n", to, subject, body)
		return nil
	}

	// Setup authentication
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)

	// Compose email
	from := cfg.SMTPFrom
	if from == "" {
		from = cfg.SMTPUser
	}

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", to, subject, body))

	// Send email
	addr := fmt.Sprintf("%s:%s", cfg.SMTPHost, cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendOTP generates and stores an OTP in memory, then sends it via email
func SendOTP(cfg *Config, key string, email string) (string, error) {
	// Generate OTP
	otpCode, err := GenerateOTP()
	if err != nil {
		return "", err
	}

	// Clean up expired OTPs periodically
	globalOTPStore.cleanupExpiredOTPs()

	// Store OTP in memory
	globalOTPStore.mu.Lock()
	globalOTPStore.otps[key] = otpEntry{
		code:      otpCode,
		expiresAt: time.Now().Add(10 * time.Minute), // OTP expires in 10 minutes
	}
	globalOTPStore.mu.Unlock()

	// Send OTP via email
	subject := "Your OTP Code"
	body := fmt.Sprintf("Your OTP code is: %s\n\nThis code will expire in 10 minutes.\n\nIf you did not request this code, please ignore this email.", otpCode)
	
	if err := SendEmail(cfg, email, subject, body); err != nil {
		// Log error but don't fail - OTP is still generated and stored
		fmt.Printf("Warning: Failed to send email to %s: %v\n", email, err)
	}

	return otpCode, nil
}

// VerifyOTP verifies an OTP code for a user from memory
func VerifyOTP(key string, otpCode string) error {
	globalOTPStore.mu.RLock()
	entry, exists := globalOTPStore.otps[key]
	globalOTPStore.mu.RUnlock()

	if !exists {
		return errors.New("invalid or expired OTP")
	}

	// Check if OTP has expired
	if time.Now().After(entry.expiresAt) {
		// Remove expired OTP
		globalOTPStore.mu.Lock()
		delete(globalOTPStore.otps, key)
		globalOTPStore.mu.Unlock()
		return errors.New("OTP has expired")
	}

	// Verify code matches
	if entry.code != otpCode {
		return errors.New("invalid OTP code")
	}

	// Remove OTP after successful verification (one-time use)
	globalOTPStore.mu.Lock()
	delete(globalOTPStore.otps, key)
	globalOTPStore.mu.Unlock()

	return nil
}

func userOTPKey(userID int64) string {
	return fmt.Sprintf("user:%d", userID)
}

func registrationOTPKey(email string) string {
	return fmt.Sprintf("registration:%s", normalizeEmail(email))
}

