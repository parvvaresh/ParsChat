package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/username/tcp-chat/internal/models"
)

type ChatService struct {
	DB        *sql.DB
	Clients   map[int]*models.Client
	Mu        sync.RWMutex
	JWTSecret []byte
	Logger    *log.Logger
}

func NewChatService(dbPath string, jwtSecret string, logger *log.Logger) (*ChatService, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	svc := &ChatService{
		DB:        db,
		Clients:   make(map[int]*models.Client),
		JWTSecret: []byte(jwtSecret),
		Logger:    logger,
	}

	if err := svc.initSchema(); err != nil {
		return nil, err
	}

	return svc, nil
}

func (s *ChatService) initSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			full_name TEXT NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			creator_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(group_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			from_user INTEGER NOT NULL,
			to_user INTEGER,
			group_id INTEGER,
			content TEXT,
			media_url TEXT,
			media_type TEXT,
			latitude REAL,
			longitude REAL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS message_reads (
			message_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(message_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS message_reactions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			emoji TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(message_id, user_id, emoji)
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_users (
			blocker_id INTEGER NOT NULL,
			blocked_id INTEGER NOT NULL,
			blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(blocker_id, blocked_id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_keys (
			user_id INTEGER PRIMARY KEY,
			public_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, statement := range statements {
		if _, err := s.DB.Exec(statement); err != nil {
			return err
		}
	}

	_, _ = s.DB.Exec("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''")
	_, _ = s.DB.Exec("ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''")

	if s.Logger != nil {
		s.Logger.Println("[OK] Database initialized")
	}

	return nil
}

func (s *ChatService) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "chat_salt_2024"))
	return hex.EncodeToString(hash[:])
}

func (s *ChatService) GenerateJWT(userID int, username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &models.Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.JWTSecret)
}

func (s *ChatService) ValidateJWT(tokenString string) (*models.Claims, error) {
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return s.JWTSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (s *ChatService) RegisterClient(userID int) *models.Client {
	client := &models.Client{
		ID:       userID,
		Messages: make(chan []byte, 100),
		Done:     make(chan bool),
	}

	s.Mu.Lock()
	s.Clients[userID] = client
	s.Mu.Unlock()

	return client
}

func (s *ChatService) UnregisterClient(userID int) {
	s.Mu.Lock()
	delete(s.Clients, userID)
	s.Mu.Unlock()
}

func (s *ChatService) SendToUser(userID int, data []byte) {
	s.Mu.RLock()
	client, ok := s.Clients[userID]
	s.Mu.RUnlock()
	if !ok {
		return
	}

	select {
	case client.Messages <- data:
	default:
	}
}

func (s *ChatService) OnlineUserIDs() []int {
	s.Mu.RLock()
	ids := make([]int, 0, len(s.Clients))
	for userID := range s.Clients {
		ids = append(ids, userID)
	}
	s.Mu.RUnlock()
	return ids
}
