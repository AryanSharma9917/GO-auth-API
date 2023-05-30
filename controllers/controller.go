package controllers

import (
	"fmt"
	"golang-auth/db"
	"net/http"
	"strconv"
	"time"

	"golang-auth/jwt"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Used to create a new user
func CreateUser(client *mongo.Client) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.QueryParam("username")
		//Check if the user exists in the Database
		dbUser, err := db.FindOne(username, "goapi-auth", "users", client)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if dbUser == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please login first")
		}
		//Checks if user is admin and perform the rest of the functions
		if dbUser.IsAdmin {
			//Parse the incoming data
			username := c.QueryParam("newUsername")
			password := c.QueryParam("newPassword")
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 8)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err)
			}
			isAdmin, err := strconv.ParseBool(c.QueryParam("isAdmin"))
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid value for 'isAdmin'"})
			}
			organization := c.QueryParam("organization")
			user := db.User{Username: username, Password: string(hashedPassword), IsAdmin: isAdmin, Organization: organization}

			// Generate a JWT token for the authenticated user
			token, err := jwt.GenerateToken(username, isAdmin)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}
			loc, err := time.LoadLocation("Asia/Kolkata")
			if err != nil {
				fmt.Println(err)
				return err
			}

			newToken := db.Tokens{
				Token:     token,
				Username:  username,
				CreatedAt: time.Now().In(loc),
				UpdatedAt: time.Now().In(loc),
				ExpiresAt: time.Now().In(loc).Add(1 * time.Hour),
			}

			db.AddToken(newToken, client)

			// Store the JWT token in the response header
			c.Response().Header().Set("Authorization", "Bearer "+token)

			// Insert the data into the database
			return db.AddUser(user, client, c)
		}

		return c.JSON(http.StatusUnauthorized, "Not authorized")
	}
}

// Used to delete an user
func DeleteUser(client *mongo.Client) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.QueryParam("username")
		//Check if the user exists in the Database
		dbUser, err := db.FindOne(username, "goapi-auth", "users", client)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if dbUser == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please login first")
		}
		//Checks if user is admin and perform the rest of the functions
		if dbUser.IsAdmin {
			// Parse the incoming data
			delUsername := c.QueryParam("delUsername")

			//Check if the user to be deleted exists in the Database
			delUser, err := db.FindOne(delUsername, "goapi-auth", "users", client)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}
			if dbUser == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid username or password")
			}

			if err2 := db.Delete(delUser.Username, client); err2 != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err2.Error())
			}
			return c.JSON(http.StatusOK, "successfully deleted")
		}

		return c.JSON(http.StatusUnauthorized, "Not authorized")
	}

}
