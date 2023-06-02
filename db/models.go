package db

import (
	"time"
)

type User struct {
	Username     string `json:"username" bson:"username"`
	Password     string `json:"password" bson:"password"`
	IsAdmin      bool   `json:"isAdmin" bson:"isAdmin"`
	Organization string `json:"organization" bson:"organization"`
}

type Tokens struct {
	Token     string    `json:"token" bson:"token"`
	Username  string    `json:"username" bson:"username"`
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt" bson:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt" bson:"expiresAt"`
}

type RevokedToken struct {
	Token string    `json:"token" bson:"token"`
	Time  time.Time `json:"time" bson:"time"`
}
