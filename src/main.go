package main

import (
	"./database"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var db *database.Database

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			fmt.Printf("[" + time.Now().Format(time.UnixDate) + "] " + r.RemoteAddr + " [" + r.Method + "] " + /*"[" +  + "] " +*/ r.URL.String() + "\n")
		},
	)
}

type httpRes struct {
	Success bool `json:"success"`
	Error bool `json:"error"`
	Message string `json:"message"`
}

func apiGET(w http.ResponseWriter, r *http.Request) {
	//w.Header().Add("status", "401")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "API!!")
}

func apiLoginPOST(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tx, _ := db.DB.Begin()

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &body)

	rows, err := db.DB.Query("SELECT * FROM users WHERE username = ?", body.Username)
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()
	rows.Next()
	var user database.User


	rows.Scan(&user.ID, &user.Username, &user.Email, &user.Hash, &user.SessionToken, &user.SessionExpires)

	if user.ID == 0 {
		// There is no user with this username, send error
		var res httpRes = httpRes{
			Success: false,
			Error: true,
			Message: "The username or password you entered is wrong, try again please!",
		}
		//w.Header().Add("status", "401")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(res)
		return
	}

	// Should check password here
	var password []byte = []byte(body.Password)
	var hash []byte = []byte(user.Hash)
	err = bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		// Incorrect password
		var res httpRes = httpRes{
			Success: false,
			Error: true,
			Message: "The username or password you entered is wrong, try again please!",
		}
		//w.Header().Add("status", "401")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(res)
		return
	}

	// Password is correct

	// Create session and send success message to client with the session info
	var s = database.NewSession()
	var res struct {
		Success bool `json:"success"`
		Error bool `json:"error"`
		Message string `json:"message"`
		Session database.Session `json:"session"`
	}

	res.Success = true
	res.Error = false
	res.Message = "You logged in successfully!"
	res.Session = s

	var cookie = http.Cookie{
		Name: "sessionToken",
		Value: s.SessionToken,
		Path: "/",
		//Domain: "fs.panictriggers.xyz", enable this when using the domain, doesn't work for localhost
		Expires: time.Unix(s.SessionExpires, 0),
	}
	http.SetCookie(w, &cookie)

	json.NewEncoder(w).Encode(res)

	// Save the session info
	statement, _ := tx.Prepare("UPDATE users SET session_token = ?, session_expires = ? WHERE username = ?")
	defer statement.Close()
	statement.Exec(s.SessionToken, s.SessionExpires, body.Username)
	tx.Commit()
	dumpUsers()
}

func apiMeGET(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, err := r.Cookie("sessionToken")

	if err != nil {
		// Session cookie is not set
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "You are not logged in!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	if len(cookie.Value) == 0 {
		// Session cookie is not set
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "You are not logged in!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	//if cookie.Expires.Unix() >= time.Now().Unix() {
	//	// Session is expired
	//	var res = httpRes{
	//		Success: false,
	//		Error: true,
	//		Message: "Your session has been expired, please log back in!",
	//	}
	//	json.NewEncoder(w).Encode(res)
	//	return
	//}

	// Check the expire time in the db, might have edited the cookie
	rows, _ := db.DB.Query("SELECT session_expires FROM users WHERE session_token = ?", cookie.Value)
	defer rows.Close()
	rows.Next()
	var sessionExpires int64
	rows.Scan(&sessionExpires)
	if time.Now().Unix() >= sessionExpires {
		// Session has indeed been expired
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "Your session has been expired, please log back in!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	fmt.Println(cookie.Value)

	// Session is valid, get the user
	rows, _ = db.DB.Query("SELECT * FROM users WHERE session_token = ?", cookie.Value)
	defer rows.Close()
	rows.Next()
	var user database.User
	rows.Scan(&user.ID, &user.Username, &user.Email, &user.Hash, &user.SessionToken, &user.SessionExpires)
	json.NewEncoder(w).Encode(user)
}

func main() {
	d, err := sql.Open("mysql",  "root:Test123@(localhost:3306)/fs.panictriggers.xyz")
	if err != nil {
		panic(err)
	}
	db = database.NewDatabase(d)

	//setupDb()

	router := mux.NewRouter().StrictSlash(true)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/", apiGET).Methods("GET")
	apiRouter.HandleFunc("/login", apiLoginPOST).Methods("POST")
	apiRouter.HandleFunc("/me", apiMeGET).Methods("GET")

	log.Fatal(http.ListenAndServe(":80", logger(router)))
}

func dumpUsers() {
	rows, _ := db.DB.Query("SELECT * FROM users")
	defer rows.Close()
	for rows.Next() {
		var user database.User

		rows.Scan(&user.ID, &user.Username, &user.Email, &user.Hash, &user.SessionToken, &user.SessionExpires)

		fmt.Printf("%+v\n", user)
	}
}

func setupDb() {
	// db setup
	s, _ := db.DB.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username VARCHAR(64), email VARCHAR(128), hash VARCHAR(512), session_token VARCHAR(128), session_expires integer)")
	_, err := s.Exec()
	if err != nil {
		panic(err.Error())
	}
	s1, _ := db.DB.Prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, location VARCHAR(512), filename VARCHAR(512), public BOOLEAN, owner INTEGER, random_name VARCHAR(128))")
	_, err = s1.Exec()
	if err != nil {
		panic(err.Error())
	}
	var password []byte = []byte("Test")
	hash, _ := bcrypt.GenerateFromPassword(password, 8)
	fmt.Println(len(hash))
	s2, _ := db.DB.Prepare("INSERT INTO users (id, username, email, hash, session_token, session_expires) VALUES (1, 'J0eppp', 'joep.van.dijk4@gmail.com', ?, 'test', 1)")
	_, err = s2.Exec(string(hash))
	if err != nil {
		panic(err.Error())
	}
}
