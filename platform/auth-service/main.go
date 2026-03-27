package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte
var adminPassword string

func init() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("secret123") // intentionally weak default
	}
	if adminPassword == "" {
		adminPassword = "admin123"
	}
}

type loginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type claims struct {
	User string `json:"user"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// POST /auth/login — issues a JWT
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	role := ""
	switch req.User {
	case "admin":
		if req.Password != adminPassword {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		role = "admin"
	case "user":
		if req.Password != "user123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		role = "user"
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Intentional vulnerability: no expiry set on token (for test 05-authentication)
	c := claims{
		User: req.User,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			// ExpiresAt intentionally omitted
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// GET /auth/validate — Traefik ForwardAuth endpoint
func validateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	// Intentional vulnerability: accepts alg:none (for test 05-authentication/jwt-tests.sh)
	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodNone); ok {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	c, ok := token.Claims.(*claims)
	if !ok {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Auth-User", c.User)
	w.Header().Set("X-Auth-Role", c.Role)
	w.WriteHeader(http.StatusOK)
}

// GET /auth/admin — privileged endpoint, requires admin role
func adminHandler(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Auth-Role")
	if role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "welcome to the admin panel",
		"data":    "internal platform configuration here",
	})
}

// GET /health
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/auth/validate", validateHandler)
	http.HandleFunc("/auth/admin", adminHandler)
	http.HandleFunc("/health", healthHandler)

	addr := ":8081"
	fmt.Printf("auth-service listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
