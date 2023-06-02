package db

import (
	"context"

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
