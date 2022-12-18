package models

import "time"

type URL struct {
	ID          string `bson:"_id" json:"id"`
	Original    string `bson:"original" json:"original"`
	Short       string `bson:"short" json:"short"`
	UserID      string `bson:"user_id" json:"userId"`
	Deactivated bool   `bson:"deactivated" json:"deactivated"`
	CreatedAt   time.Time `bson:"created_at" json:"createdAt"`
}
type URLResponse struct {
	ID          string `bson:"_id" json:"id"`
	Original    string `bson:"original" json:"original"`
	Short       string `bson:"short" json:"short"`
	Deactivated bool   `bson:"deactivated" json:"deactivated"`
	CreatedAt   time.Time `bson:"created_at" json:"createdAt"`
}