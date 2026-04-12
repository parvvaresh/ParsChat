package models

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Client struct {
	ID       int
	Username string
	Messages chan []byte
	Done     chan bool
}

type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	FullName  string `json:"fullName"`
	Bio       string `json:"bio,omitempty"`
	AvatarURL string `json:"avatarUrl,omitempty"`
}

type Message struct {
	ID        int        `json:"id,omitempty"`
	Type      string     `json:"type"`
	Content   string     `json:"content,omitempty"`
	From      int        `json:"from,omitempty"`
	To        int        `json:"to,omitempty"`
	GroupID   int        `json:"groupId,omitempty"`
	MediaURL  string     `json:"mediaUrl,omitempty"`
	MediaType string     `json:"mediaType,omitempty"`
	Latitude  *float64   `json:"latitude,omitempty"`
	Longitude *float64   `json:"longitude,omitempty"`
	Timestamp int64      `json:"timestamp,omitempty"`
	IsRead    bool       `json:"isRead,omitempty"`
	Reactions []Reaction `json:"reactions,omitempty"`
}

type Reaction struct {
	ID        int    `json:"id"`
	MessageID int    `json:"messageId"`
	UserID    int    `json:"userId"`
	Emoji     string `json:"emoji"`
	UserName  string `json:"userName,omitempty"`
}

type Group struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Creator int    `json:"creator"`
}
