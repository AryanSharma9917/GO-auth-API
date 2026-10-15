package routes

import (
	"golang-auth/configs"
	"golang-auth/controllers"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
)

func InitRoutes(e *echo.Echo, client *mongo.Client, cfg configs.Config) {

	//PUBLIC ROUTES
	// e.POST("/register", controllers.CreateUser(client))
	e.POST("/login", controllers.LoginUser(client, cfg))
	e.POST("/logout", controllers.LogoutUser(client, cfg))
	e.POST("/refresh", controllers.RefreshToken(client, cfg))

	//USER ROUTES
	e.GET("/", controllers.GetUsers(client))

	//ADMIN ROUTES
	e.POST("/add", controllers.CreateUser(client, cfg))
	e.POST("/delete", controllers.DeleteUser(client))

}
