package models

type UserID string

type USER struct{
	ID			string `bson:"_id"`
	Email		string `bson:"email"`
	Password	string `bson:"password"`
}