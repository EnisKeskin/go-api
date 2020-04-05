package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	COUNT   string `json:"count"`
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

	updatePost := Chain(updatePost, loggingMiddleware())
	router.HandleFunc("/posts/{id}", updatePost).Methods("PUT")

	deletePost := Chain(deletePost, loggingMiddleware())
	router.HandleFunc("/posts/{id}", deletePost).Methods("DELETE")

	// headersOk := handlers.AllowedHeaders([]string{"X-Requested-With"})
	// originsOk := handlers.AllowedOrigins([]string{os.Getenv("ORIGIN_ALLOWED")})
	// methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	http.ListenAndServe(":8000", (router))
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	postId := mux.Vars(r)["id"]
	smt, err := database.Prepare("DELETE FROM post WHERE id=?")
	if err != nil {
		fmt.Print(err)
		return
	}
	smt.Exec(postId)
	w.WriteHeader(http.StatusOK)
}

func updatePost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var post Post
	postId := mux.Vars(r)["id"]
	_ = json.NewDecoder(r.Body).Decode(&post)
	smt, err := database.Prepare("UPDATE post SET post_message = ? WHERE post.user_id=? AND id =?;")
	if err != nil {
		fmt.Print(err)
		return
	}
	smt.Exec(post.MESSAGE, userId, postId)
	w.WriteHeader(http.StatusOK)
}

func createPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	date := date()
	var post Post
	var postTemp PostGet
	var posts []PostGet
	_ = json.NewDecoder(r.Body).Decode(&post)

	stm, err := database.Prepare("INSERT INTO post (user_id, post_message, post_date) VALUES (?, ?, ?)")
	if err != nil {
		fmt.Print(err)
		return
	}
	stm.Exec(userId, post.MESSAGE, date)

	newPostCount, _ := strconv.ParseInt(postCount(), 10, 64)
	lastPostCount, _ := strconv.ParseInt(post.COUNT, 10, 64)
	count := newPostCount - lastPostCount
	rows, err := database.Query("SELECT post_message, post_date,username FROM post INNER JOIN user ON post.user_id = user.id ORDER BY post.id DESC LIMIT ?", count)
	if err != nil {
		fmt.Print(err)
		return
	}

	for rows.Next() {
		rows.Scan(&postTemp.MESSAGE, &postTemp.DATE, &postTemp.USERNAME)
		posts = append(posts, postTemp)

	}

	json.NewEncoder(w).Encode(posts)

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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	var user User
	var id string
	_ = json.NewDecoder(r.Body).Decode(&user)
	fmt.Println(user)
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
	fmt.Println(id)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println(tokenString)
	smt, err := database.Prepare("UPDATE user SET token=? WHERE id=?")
	if err != nil {
		fmt.Print(err)
		return
	}
	smt.Exec(tokenString, id)
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

func date() string {
	t := time.Now()
	date := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	return date
}

func postCount() string {
	var count string
	row, err := database.Query("SELECT COUNT(*) count FROM post")
	if err != nil {
		fmt.Print(err)
		return ""
	}
	for row.Next() {
		row.Scan(&count)
	}
	return count
}
