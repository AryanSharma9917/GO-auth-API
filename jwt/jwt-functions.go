package jwt

import (
	"fmt"
	"golang-auth/configs"
	"golang-auth/db"
	"time"

	"github.com/golang-jwt/jwt"

	"go.mongodb.org/mongo-driver/mongo"
)

// Used to generate a new token
func GenerateToken(username string, isAdmin bool) (string, error) {
	// Set the expiration time for the token
	expirationTime := time.Now().Add(1 * time.Hour)

	// Create the JWT claims
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["username"] = username
	claims["exp"] = expirationTime
	claims["isAdmin"] = isAdmin

	// Generate the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := []byte(configs.Cfg.JwtSecret)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Used to refresh a token
func GenerateRefreshToken(userID string) (string, error) {
	// Set the expiration time for the refresh token
	expirationTime := time.Now().Add(24 * time.Hour)

	// Create the JWT claims
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["user_id"] = userID
	claims["exp"] = expirationTime

	// Generate the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := []byte(configs.Cfg.JwtSecret)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Used to revoke a token
func RevokeToken(tokenString string, client *mongo.Client) error {

	// Parse the token
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		fmt.Println("first:")
		fmt.Println(tokenString)
		fmt.Println("second:")
		fmt.Println(token)

		loc, err2 := time.LoadLocation("Asia/Kolkata")
		if err2 != nil {
			fmt.Println(err2)
		}

		fmt.Println(time.Now().In(loc))

		return []byte(configs.Cfg.JwtSecret), nil
	})
	if err != nil {
		fmt.Println("Error parsing token:", err)
		return err
	}

	// Add the token to the blacklist collection
	blackToken := db.RevokedToken{
		Token: tokenString,
		Time:  time.Now(),
	}
	if err := db.AddTokenToBlacklist(blackToken, client); err != nil {
		fmt.Println("Error adding token to blacklist:", err)
		return err
	}

	return nil
}
