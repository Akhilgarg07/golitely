package main

import (
	"context"
	"encoding/json"
	"fmt"
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

type URL struct{
	ID	string `bson:"_id"`
	Original	string `bson:"original"`
	Expiry	time.Time `bson:"expiry"`
	UserID	string `bson:"user_id"`
	Deactivated	bool `bson:"deactivated"`
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
	router.HandleFunc("/urls", authMiddleware(createURLHandler(urlsColl, jwtSecret), jwtSecret)).Methods("POST")
	// router.HandleFunc("/urls/{id}", authMiddleware(viewURLHandler(urlsColl, jwtSecret), jwtSecret)).Methods("GET")
	// router.HandleFunc("/urls", authMiddleware(getURLsHandler(urlsColl, jwtSecret), jwtSecret)).Methods("GET")
	// router.HandleFunc("/urls/{id}/deactivate", authMiddleware(getURLsHandler(urlsColl, jwtSecret), jwtSecret)).Methods("PUT")
	// router.HandleFunc("/urls/{id}/activate", authMiddleware(getURLsHandler(urlsColl, jwtSecret), jwtSecret)).Methods("PUT")

	fmt.Print(http.ListenAndServe(":8000", router))
}

func validateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return re.MatchString(email)
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
	fmt.Println(tokenString)
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
	fmt.Println(claims)
	userId, ok := claims["id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	fmt.Println(userId)
	return userId, nil

}

func authMiddleware(next http.HandlerFunc, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		userId, err := getUserIDFromJWT(r, jwtSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		fmt.Println(userId)
		ctx := context.WithValue(r.Context(), "user_id", userId)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func validateURL(url string) bool {
	re := regexp.MustCompile(`^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$`)
	return re.MatchString(url)
}

func createURLHandler(urlsColl *mongo.Collection, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "application/json")
		userId := r.Context().Value("user_id").(string)
		if userId == "" {
			http.Error(w, "Cannot verify user", http.StatusBadRequest)
			return
		}
		fmt.Println(userId)
		var url URL
		if err := json.NewDecoder(r.Body).Decode(&url); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		if url.Expiry.IsZero() {
			url.Expiry = time.Now().Add(24 * time.Hour)
		}

		if !validateURL(url.Original) {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		url.ID = primitive.NewObjectID().Hex()
		url.UserID = userId
		
		if _, err := urlsColl.InsertOne(context.TODO(), url); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(url)

	}
}