package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	mongodbURI = "mongodb://localhost:27017"
	jwtSecret = "mysecret"
)

type User struct{
	ID			string `bson:"_id"`
	Email		string `bson:"email"`
	Password	string `bson:"password"`
}

type URL struct {
	ID          string `bson:"_id" json:"id"`
	Original    string `bson:"original" json:"original"`
	Short       string `bson:"short" json:"short"`
	UserID      string `bson:"user_id" json:"userId"`
	Deactivated bool   `bson:"deactivated" json:"deactivated"`
}
type URLResponse struct {
	ID          string `bson:"_id" json:"id"`
	Original    string `bson:"original" json:"original"`
	Short       string `bson:"short" json:"short"`
	Deactivated bool   `bson:"deactivated" json:"deactivated"`
}

func main(){
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongodbURI))
	if err != nil {
		fmt.Print(err)
		return
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Connected to MongoDB")

	usersColl := client.Database("url_shortner").Collection("users")
	urlsColl := client.Database("url_shortner").Collection("urls")

	router := mux.NewRouter()
	router.HandleFunc("/signup", signupHandler(usersColl)).Methods("POST")
	router.HandleFunc("/login", loginHandler(usersColl)).Methods("POST")
	router.HandleFunc("/urls", authMiddleware(createURLHandler(urlsColl), jwtSecret)).Methods("POST")
	router.HandleFunc("/urls/{id}", authMiddleware(viewURLHandler(urlsColl), jwtSecret)).Methods("GET")
	router.HandleFunc("/urls", authMiddleware(viewURLsHandler(urlsColl), jwtSecret)).Methods("GET")
	router.HandleFunc("/urls/{id}", authMiddleware(deleteURLHandler(urlsColl), jwtSecret)).Methods("DELETE")
	router.HandleFunc("/urls/{id}/deactivate", authMiddleware(deactivateURLHandler(urlsColl), jwtSecret)).Methods("PUT")
	router.HandleFunc("/urls/{id}/activate", authMiddleware(activateURLHandler(urlsColl), jwtSecret)).Methods("PUT")
	router.HandleFunc("/{key}", redirectHandler(urlsColl)).Methods("GET")

	fmt.Print(http.ListenAndServe(":8000", router))
}

func validateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return re.MatchString(email)
}

func deleteURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value("user_id").(string)
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

func activateURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value("user_id").(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url URL
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

func deactivateURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value("user_id").(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		fmt.Println(id, userId)
		var url URL
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

func signupHandler(userColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if user.Email == "" || user.Password == "" {
			http.Error(w, "Invalid Input", http.StatusBadRequest)
			return
		}

		if !validateEmail(user.Email){
			http.Error(w, "Enter valid email", http.StatusBadRequest)
			return
		}

		var existingUser User
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

func loginHandler(userColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !validateEmail(user.Email) || len(user.Password) < 8 {
			http.Error(w, "Invalid email or password", http.StatusBadRequest)
			return
		}

		var existingUser User
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

func getUserIDFromJWT(r *http.Request, jwtSecret string) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}
	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 {
		return "", fmt.Errorf("invalid authorization header")
	}
	tokenString := bearerToken[1]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok{
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil{
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid{
		return "", fmt.Errorf("invalid token")
	}
	userId, ok := claims["id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	return userId, nil

}

func authMiddleware(next http.HandlerFunc, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		userId, err := getUserIDFromJWT(r, jwtSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user_id", userId)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func validateURL(url string) bool {
	re := regexp.MustCompile(`^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$`)
	return re.MatchString(url)
}

// from https://siongui.github.io/2015/04/13/go-generate-random-string/
func getRandomString(strlen int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func createURLHandler(urlsColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		userId := r.Context().Value("user_id").(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url URL
		if err := json.NewDecoder(r.Body).Decode(&url); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !validateURL(url.Original) {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		url.ID = primitive.NewObjectID().Hex()
		url.UserID = userId
		
		url.Short = getRandomString(8)

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

func redirectHandler(urlsColl *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the shortened URL key from the path
		vars := mux.Vars(r)
		key := vars["key"]

		var url URL
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

func viewURLHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "Cannot find id", http.StatusBadRequest)
			return
		}
		userId := r.Context().Value("user_id").(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		var url URLResponse
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

func viewURLsHandler(urlsColl *mongo.Collection) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		userId := r.Context().Value("user_id").(string)
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

		var URLs []URLResponse
		for cur.Next(context.TODO()) {
			var url URLResponse
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