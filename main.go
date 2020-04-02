package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

var database, _ = sql.Open("sqlite3", "./post.db")
var jwtKey = []byte("kartaca")
var userId string

type Middleware func(http.HandlerFunc) http.HandlerFunc

type User struct {
	ID       string `json:"id"`
	USERNAME string `json:"username"`
	PASSWORD string `json:"password"`
}

type Claims struct {
	ID string
	jwt.StandardClaims
}

var posts []User

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	var id string
	_ = json.NewDecoder(r.Body).Decode(&user)
	rows, _ := database.Query("SELECT id FROM user WHERE username=? AND password=?", user.USERNAME, user.PASSWORD)

	for rows.Next() {
		rows.Scan(&id)
		getToken(w, id)
	}
}

func Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}
	return f
}

func getToken(w http.ResponseWriter, id string) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func loggingMiddleware() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie("token")
			fmt.Print("1")
			if err != nil {
				if err == http.ErrNoCookie {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			tknStr := c.Value

			claims := &Claims{}

			tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})
			fmt.Print("2")
			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					http.Error(w, "StatusUnauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "StatusBadRequest", http.StatusBadRequest)
				return
			}
			fmt.Print("3")
			if !tkn.Valid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			userId = claims.ID
			fmt.Print("4")
			// Do stuff here
			//http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, "/login"), 302)
			log.Println(r.RequestURI)
			// Call the next handler, which can be another middleware in the chain, or the final handler.
			next.ServeHTTP(w, r)
		}
	}
}

func main() {
	router := mux.NewRouter()

	// train := Chain(, loggingMiddleware())
	// router.HandleFunc("/token", train).Methods("GET")
	router.HandleFunc("/login", login).Methods("POST")
	// router.HandleFunc("/posts", createPost).Methods("POST")
	// router.HandleFunc("/posts/{id}", getPost).Methods("GET")
	// router.HandleFunc("/posts/{id}", updatePost).Methods("PUT")
	// router.HandleFunc("/posts/{id}", deletePost).Methods("DELETE")
	http.ListenAndServe(":8000", router)
}

// func createPost(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	var post Post
// 	_ = json.NewDecoder(r.Body).Decode(&post)
// 	fmt.Println(post)
// 	post.ID = strconv.Itoa(rand.Intn(1000000))
// 	posts = append(posts, post)
// 	json.NewEncoder(w).Encode(&post)
// }
// func getPost(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	params := mux.Vars(r)
// 	for _, item := range posts {
// 		if item.ID == params["id"] {
// 			json.NewEncoder(w).Encode(item)
// 			return
// 		}
// 	}
// 	json.NewEncoder(w).Encode(&Post{})
// }
// func updatePost(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	params := mux.Vars(r)
// 	for index, item := range posts {
// 		if item.ID == params["id"] {
// 			posts = append(posts[:index], posts[index+1:]...)
// 			var post Post
// 			_ = json.NewDecoder(r.Body).Decode(&post)
// 			post.ID = params["id"]
// 			posts = append(posts, post)
// 			json.NewEncoder(w).Encode(&post)
// 			return
// 		}
// 	}
// 	json.NewEncoder(w).Encode(posts)
// }
// func deletePost(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	params := mux.Vars(r)
// 	for index, item := range posts {
// 		if item.ID == params["id"] {
// 			posts = append(posts[:index], posts[index+1:]...)
// 			break
// 		}
// 	}
// 	json.NewEncoder(w).Encode(posts)
// }
