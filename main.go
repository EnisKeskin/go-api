package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

type Post struct {
	USERID  string `json:"userId"`
	MESSAGE string `json:"message"`
	DATE    string `json:"date"`
}

type PostGet struct {
	USERNAME string `json:"username"`
	MESSAGE  string `json:"message"`
	DATE     string `json:"date"`
}

type Claims struct {
	ID string
	jwt.StandardClaims
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/login", login).Methods("POST")
	createPost := Chain(createPost, loggingMiddleware())
	router.HandleFunc("/posts", createPost).Methods("POST")
	getPost := Chain(getPost, loggingMiddleware())
	router.HandleFunc("/posts", getPost).Methods("GET")
	simpleGetPost := Chain(simpleGetPost, loggingMiddleware())
	router.HandleFunc("/posts/{id}", simpleGetPost).Methods("GET")
	// router.HandleFunc("/posts/{id}", updatePost).Methods("PUT")
	// router.HandleFunc("/posts/{id}", deletePost).Methods("DELETE")
	http.ListenAndServe(":8000", router)
}

func createPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	date := date()
	lastPostCount := mux.Vars(r)["count"]
	var post Post
	_ = json.NewDecoder(r.Body).Decode(&post)

	stm, err := database.Prepare("INSERT INTO post (user_id, post_message, post_date) VALUES (?, ?, ?)")
	if err != nil {
		fmt.Print(err)
		return
	}
	stm.Exec(userId, post.MESSAGE, date)
	count := postCount()
	fmt.Printf(count)
	fmt.Printf(lastPostCount)
}

func simpleGetPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var posts PostGet
	postId := mux.Vars(r)["id"]
	rows, _ := database.Query("SELECT post_message, post_date,username FROM post INNER JOIN user ON post.user_id = user.id WHERE post.id=?", postId)

	for rows.Next() {
		rows.Scan(&posts.MESSAGE, &posts.DATE, &posts.USERNAME)
	}
	json.NewEncoder(w).Encode(posts)
}

func getPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var postTemp PostGet
	var posts []PostGet
	rows, _ := database.Query("SELECT post_message, post_date,username FROM post INNER JOIN user ON post.user_id = user.id")

	for rows.Next() {
		rows.Scan(&postTemp.MESSAGE, &postTemp.DATE, &postTemp.USERNAME)
		posts = append(posts, postTemp)

	}
	json.NewEncoder(w).Encode(posts)
}

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
	expirationTime := time.Now().Add(50 * time.Hour)
	claims := &Claims{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	fmt.Print(tokenString)
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
			if err != nil {
				if err == http.ErrNoCookie {
					http.Error(w, "StatusUnauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "StatusBadRequest", http.StatusBadRequest)
				return
			}

			tknStr := c.Value

			claims := &Claims{}
			tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})
			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					http.Error(w, "StatusUnauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "StatusBadRequest", http.StatusBadRequest)
				return
			}
			if !tkn.Valid {
				http.Error(w, "StatusUnauthorized", http.StatusUnauthorized)
				return
			}

			userId = claims.ID
			//http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, "/login"), 302)

			next.ServeHTTP(w, r)
		}
	}
}

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
