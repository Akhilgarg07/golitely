package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/akhilgarg07/golitely/source/models"
	"github.com/akhilgarg07/golitely/source/utils"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)


var	jwtSecret = os.Getenv("jwtSecret")

func SignupHandler(userColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		var user models.USER
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if user.Email == "" || user.Password == "" {
			http.Error(w, "Invalid Input", http.StatusBadRequest)
			return
		}

		if !utils.ValidateEmail(user.Email){
			http.Error(w, "Enter valid email", http.StatusBadRequest)
			return
		}

		var existingUser models.USER
		err := userColl.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
		if err == nil {
			http.Error(w, "User already exists", http.StatusBadRequest)
			return
		}

		user.ID= primitive.NewObjectID().Hex()
		if _, err := userColl.InsertOne(context.TODO(), user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id": user.ID,
			"email": user.Email,
			"expiry": time.Now().Add(time.Hour*24).Unix(),
		}).SignedString([]byte(jwtSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"id": user.ID,
			"email": user.Email,
			"token": token,
			"message": "user created successfully",
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func LoginHandler(userColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		var user models.USER
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !utils.ValidateEmail(user.Email) || len(user.Password) < 8 {
			http.Error(w, "Invalid email or password", http.StatusBadRequest)
			return
		}

		var existingUser models.USER
		err := userColl.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
		if err != nil {
			if err == mongo.ErrNoDocuments{
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retireve user", http.StatusBadRequest)
			return
		}

		if existingUser.Password != user.Password {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
			jwt.MapClaims{
				"id": existingUser.ID,
				"email": user.Email,
				"expiry": time.Now().Add(time.Hour*24).Unix(),
			}).SignedString([]byte(jwtSecret))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		
		response := map[string]string{
			"token": token,
			"message": "logged in successfully",
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}