package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/akhilgarg07/golitely/source/models"
	"github.com/akhilgarg07/golitely/source/utils"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateURLHandler(urlsColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url models.URL
		if err := json.NewDecoder(r.Body).Decode(&url); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !utils.ValidateURL(url.Original) {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		url.ID = primitive.NewObjectID().Hex()
		url.UserID = userId
		
		url.Short = utils.GetRandomString(8)

		now := time.Now()
		url.CreatedAt = now

		if _, err := urlsColl.InsertOne(context.TODO(), url); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)

		response := map[string]string{
			"original": url.Original,
			"shorten": "http://"+ r.Host+"/"+url.Short,
			"key": url.Short,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func RedirectHandler(urlsColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the shortened URL key from the path
		vars := mux.Vars(r)
		key := vars["key"]

		var url models.URL
		if err := urlsColl.FindOne(context.TODO(), bson.M{"short": key}).Decode(&url); err != nil {
			http.Error(w, "URL not found", http.StatusNotFound)
			return
		}

		if url.Deactivated {
			http.Error(w, "URL no longer active", http.StatusNotFound)
			return
		}

		http.Redirect(w, r, url.Original, http.StatusFound)
	}
}

func ViewURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url models.URLResponse
		if err := urlsColl.FindOne(context.TODO(), bson.M{"_id": id, "user_id": userId}).Decode(&url); err != nil {
			http.Error(w, "Error finding URL", http.StatusInternalServerError)
			return
		}

		if err := json.NewEncoder(w).Encode(url); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func ViewURLsHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		cur, err := urlsColl.Find(context.TODO(), bson.M{"user_id": userId})
		if err != nil {
			http.Error(w, "Error finding URLs", http.StatusInternalServerError)
			return
		}
		defer cur.Close(context.TODO())

		var URLs []models.URLResponse
		for cur.Next(context.TODO()) {
			var url models.URLResponse
			err := cur.Decode(&url)
			if err != nil {
				http.Error(w, "Error decoding URL", http.StatusInternalServerError)
				return
			}
			URLs = append(URLs, url)
		}

		if err := cur.Err(); err != nil {
			http.Error(w, "Error iterating over URLs cursor", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(URLs)

		if err := json.NewEncoder(w).Encode(URLs); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func DeleteURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		_, err := urlsColl.DeleteOne(context.TODO(), bson.M{"_id": id, "user_id": userId})
		if err != nil {
			http.Error(w, "Error deleting URL", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"message": "url deleted successfully",
		}

		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func ActivateURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url models.URL
		err := urlsColl.FindOne(context.TODO(), bson.M{"_id": id,"user_id": userId}).Decode(&url)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "URL not found", http.StatusNotFound)
			} else {
				http.Error(w, "Error finding URL", http.StatusInternalServerError)
			}
			return
		}

		if !url.Deactivated{
			http.Error(w, "URL already active", http.StatusInternalServerError)
			return
		}

		url.Deactivated = false
		_, err = urlsColl.ReplaceOne(context.TODO(), bson.M{"_id": id}, url)
		if err != nil {
			http.Error(w, "Error updating URL", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"message": "url activated successfully",
		}

		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}

func DeactivateURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value(models.UserID("user_id")).(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		fmt.Println(id, userId)
		var url models.URL
		err := urlsColl.FindOne(context.TODO(), bson.M{"_id": id,"user_id": userId}).Decode(&url)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "URL not found", http.StatusNotFound)
			} else {
				http.Error(w, "Error finding URL", http.StatusInternalServerError)
			}
			return
		}

		if url.Deactivated{
			http.Error(w, "URL already deactived", http.StatusInternalServerError)
			return
		}

		url.Deactivated = true
		_, err = urlsColl.ReplaceOne(context.TODO(), bson.M{"_id": id}, url)
		if err != nil {
			http.Error(w, "Error updating URL", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"message": "url deactiavted successfully",
		}

		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}
}