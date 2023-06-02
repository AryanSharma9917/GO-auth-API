package db

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Used to find one user
func FindOne(username string, db string, collection string, client *mongo.Client) (*User, error) {
	var user User
	coll := client.Database(db).Collection(collection)
	err := coll.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// Used to delete one user
func Delete(username string, client *mongo.Client) error {

	coll := client.Database("goapi-auth").Collection("users")
	filter := bson.D{{Key: "username", Value: username}}
	result, err := coll.DeleteOne(context.TODO(), filter)
	if err != nil {
		return err
	}

	fmt.Printf("Number of documents deleted: %d\n", result.DeletedCount)
	return nil
}

// Used to find all the users in the database
func FindAll(client *mongo.Client, org string) ([]User, error) {
	coll := client.Database("goapi-auth").Collection("users")
	filter := bson.D{{Key: "organization", Value: org}}
	cursor, err := coll.Find(context.TODO(), filter)
	if err != nil {
		return nil, err
	}
	var results []User
	if err = cursor.All(context.TODO(), &results); err != nil {
		return nil, err
	}
	return results, nil
}

// AddUser adds a new user to the database
func AddUser(user User, client *mongo.Client, c echo.Context) error {
	coll := client.Database("goapi-auth").Collection("users")

	_, err := coll.InsertOne(context.Background(), user)
	if err != nil {
		// If there was an error inserting the document, return an error response
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User added successfully"})
}

// AddToken adds a new JWT token to the database
func AddToken(token Tokens, client *mongo.Client) error {
	coll := client.Database("goapi-auth").Collection("tokens")

	_, err := coll.InsertOne(context.Background(), token)
	return err
}

// Used to update a token in the db
func UpdateToken(username string, client *mongo.Client, token string, c echo.Context) error {
	coll := client.Database("goapi-auth").Collection("tokens")
	filter := bson.D{{Key: "username", Value: username}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: token}, {Key: "updatedAt", Value: time.Now()}}}}
	result, err := coll.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return err
	}
	log.Printf("UpdateToken: matched %v documents and modified %v documents\n", result.MatchedCount, result.ModifiedCount)
	return nil
}

// Used to add a token to the blacklisted tokens
func AddTokenToBlacklist(token RevokedToken, client *mongo.Client) error {
	coll := client.Database("goapi-auth").Collection("blacklisted-tokens")
	_, err := coll.InsertOne(context.Background(), token)
	return err
}
