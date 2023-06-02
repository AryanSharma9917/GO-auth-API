package db

import (
	"go.mongodb.org/mongo-driver/mongo"
)

// Used to find one user
func FindOne(username string, db string, collection string, client *mongo.Client) (*User, error) {

}
