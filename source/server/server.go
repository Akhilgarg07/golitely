package server

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/akhilgarg07/golitely/source/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var	jwtSecret = os.Getenv("jwtSecret")
var mongodbURI = "mongodb://localhost:27017"

func Serve() {
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
	router.HandleFunc("/signup", handlers.SignupHandler(usersColl)).Methods("POST")
	router.HandleFunc("/login", handlers.LoginHandler(usersColl)).Methods("POST")
	router.HandleFunc("/urls", handlers.AuthMiddleware(handlers.CreateURLHandler(urlsColl), jwtSecret)).Methods("POST")
	router.HandleFunc("/urls/{id}", handlers.AuthMiddleware(handlers.ViewURLHandler(urlsColl), jwtSecret)).Methods("GET")
	router.HandleFunc("/urls", handlers.AuthMiddleware(handlers.ViewURLsHandler(urlsColl), jwtSecret)).Methods("GET")
	router.HandleFunc("/urls/{id}", handlers.AuthMiddleware(handlers.DeleteURLHandler(urlsColl), jwtSecret)).Methods("DELETE")
	router.HandleFunc("/urls/{id}/deactivate", handlers.AuthMiddleware(handlers.DeactivateURLHandler(urlsColl), jwtSecret)).Methods("PUT")
	router.HandleFunc("/urls/{id}/activate", handlers.AuthMiddleware(handlers.ActivateURLHandler(urlsColl), jwtSecret)).Methods("PUT")
	router.HandleFunc("/{key}", handlers.RedirectHandler(urlsColl)).Methods("GET")

	fmt.Print(http.ListenAndServe(":8000", router))
}
