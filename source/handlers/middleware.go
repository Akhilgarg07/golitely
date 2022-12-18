package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/akhilgarg07/golitely/source/models"
	"github.com/golang-jwt/jwt/v4"
)

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

func AuthMiddleware(next http.HandlerFunc, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		userId, err := getUserIDFromJWT(r, jwtSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), models.UserID("user_id"), userId)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
