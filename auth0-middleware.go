package auth0middleware

import (
	"bytes"
	"encoding/json"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/gorilla/context"
)

// Options ...
type Options struct {
	Endpoint   string
	ContextKey string
}

// Auth0Middleware ...
type Auth0Middleware struct {
	Options Options
}

// Auth0Body ...
type Auth0Body struct {
	Token string `json:"id_token"`
}

// TokenInfo ...
type TokenInfo struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	ClientID      string `json:"clientID"`
	Picture       string `json:"picture"`
	Nickname      string `json:"nickname"`
	Name          string `json:"name"`
}

// New ...
func New(options Options) *Auth0Middleware {
	auth0Middleware := new(Auth0Middleware)
	auth0Middleware.Options = options
	return auth0Middleware
}

func (c *Auth0Middleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Check if token is provided in the header of the request
	authToken, err := jwtmiddleware.FromAuthHeader(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if authToken == "" {
		http.Error(rw, "No token provided", http.StatusBadRequest)
		return
	}

	// Ask the auth0 server if the token is valid and retrieve the user
	body := Auth0Body{
		Token: authToken,
	}
	buffer := new(bytes.Buffer)
	json.NewEncoder(buffer).Encode(body)
	response, _ := http.Post(c.Options.Endpoint+"/tokeninfo", "application/json; charset=utf-8", buffer)

	// Check if an error occurred
	if response.StatusCode != 200 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)
		s := buf.String()
		http.Error(rw, s, response.StatusCode)
		return
	}

	// Add tokeninfo to the context
	tokenInfo := new(TokenInfo)
	decoder := json.NewDecoder(response.Body)
	decoder.Decode(&tokenInfo)
	context.Set(r, c.Options.ContextKey, tokenInfo)

	// Go on
	next(rw, r)
}
