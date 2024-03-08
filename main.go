package main

import (
	"fmt"
	"golang-auth/bot" // Import the bot package
	"golang-auth/configs"
	"golang-auth/db"
	"golang-auth/routes"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/labstack/echo/v4"
)

var e = echo.New()

func init() {
	// Initialize the cleanenv package
	err := cleanenv.ReadEnv(&configs.Cfg)
	fmt.Printf("%v", configs.Cfg)
	if err != nil {
		e.Logger.Fatal("Unable to load configuration")
	}

	// Setup database connection
	cl, err := db.ConnectDB()
	if err != nil {
		e.Logger.Fatal("Unable to connect to database")
	}

	// Initialize the bot
	myBot := bot.NewBot()

	// Set up the routes
	routes.InitRoutes(e, cl, myBot) // Pass the bot instance to the routes
}

func main() {
	// Start the server
	e.Logger.Fatal(e.Start(fmt.Sprintf("localhost:%s", configs.Cfg.Port)))
}
