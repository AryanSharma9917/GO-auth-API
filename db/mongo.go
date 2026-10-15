package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Used to connect to a database
func ConnectDB(ctx context.Context, uri string) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, err
	}

	// Ping the database to verify connection
	var result bson.M
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Decode(&result); err != nil {
		return nil, err
	}

	fmt.Println("Connected to MongoDB")
	return client, nil
}
