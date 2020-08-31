package main

import (
	"./database"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var db *database.Database

func sendMail(recipient string, title string, body string) error {
	// Set up authentication information
	from := "fs@panictriggers.xyz"
	auth := smtp.PlainAuth("fs", from, "verysafefspassword", "smtp.domain.com")

	// Connect to the server, authenticate, set the sender and recipient and send the email
	to := []string{recipient}
	msg := []byte("To: " + recipient + "\r\n" +
			"From: " + from + "\r\n" +
			"Subject: " + title + "\n\r" +
			"\r\n" +
			body + "\n\r")

	err := smtp.SendMail("smtp.domain.com:587", auth, from, to, msg)
	return err
}

func sendMail2(recipient string, title string, body string) error {
	// Set up authentication information
	auth := smtp.PlainAuth("", "security@panictriggers.xyz", "pwd", "smtp.domain.com")

	// Connect to the server, authenticate, set the sender and recipient and send the email
	to := []string{recipient}
	msg := []byte("To: " + recipient + "\r\n" +
		"From: " + "security@panictriggers.xyz\r\n" +
		"Subject: " + title + "\n\r" +
		"\r\n" +
		body + "\n\r")

	err := smtp.SendMail("smtp.domain.com:587", auth, "security@panictriggers.xyz", to, msg)
	return err
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			fmt.Printf("[" + time.Now().Format(time.UnixDate) + "] " + r.RemoteAddr + " [" + r.Method + "] " + /*"[" +  + "] " +*/ /*r.URL.String()*/ r.Host + r.URL.String() + "\n")
		},
	)
}

func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
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

			// Check the expire time in the db, might have edited the cookie
			rows, _ := db.DB.Query("SELECT id, session_expires FROM users WHERE session_token = ?", cookie.Value)
			defer rows.Close()
			rows.Next()
			var id int64
			var sessionExpires int64
			rows.Scan(&id, &sessionExpires)
			if id == 0 {
				// Invalid session token
				var res = httpRes{
					Success: false,
					Error: true,
					Message: "Your session token is invalid, please log in again!",
				}
				json.NewEncoder(w).Encode(res)
				return
			}
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

			// Session is valid
			next.ServeHTTP(w, r)
		},
	)
}

func authenticateFE(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("sessionToken")

			if err != nil  {
				// sessionToken cookie is not set
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			if  len(cookie.Value) == 0 {
				// sessionToken cookie is not set
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Check the expire time in the db, might have edited the cookie
			rows, _ := db.DB.Query("SELECT id, session_expires FROM users WHERE session_token = ?", cookie.Value)
			defer rows.Close()
			rows.Next()
			var id int64
			var sessionExpires int64
			rows.Scan(&id, &sessionExpires)
			if id == 0 {
				// Invalid session token
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if time.Now().Unix() >= sessionExpires {
				// Session has indeed been expired
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Session is valid
			next.ServeHTTP(w, r)
		},
	)
}

func createServerName() uuid.UUID {
	_uuid, _ := uuid.NewV4()
	rows, _ := db.DB.Query("SELECT id FROM files WHERE server_name = ?", _uuid.String())
	rows.Next()
	var _id int64
	rows.Scan(&_id)
	if _id != 0 {
		// ServerName already exists, create a new one
		return createServerName()
	} else {
		return _uuid
	}
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
}

func apiMeGET(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, _ := r.Cookie("sessionToken")

	// Session is valid, get the user
	rows, _ := db.DB.Query("SELECT * FROM users WHERE session_token = ?", cookie.Value)
	defer rows.Close()
	rows.Next()
	var user database.User
	rows.Scan(&user.ID, &user.Username, &user.Email, &user.Hash, &user.SessionToken, &user.SessionExpires)
	json.NewEncoder(w).Encode(user)
}

func apiUploadPOST(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, _ := r.Cookie("sessionToken")

	// User has already been authenticated with the `authenticate` middleware function

	public, err := strconv.ParseBool(r.Header.Get("File-Public"))
	if err != nil {
		// File-Public header wasn't set properly, file upload failed
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "The File-Public header wasn't set properly, it only can be `true` or `false`, please try again with the right header value!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	// Parse multipart/form-data input
	r.ParseMultipartForm(0 << 10)

	// Retrieve the file
	file, handler, err := r.FormFile("file")
	if err != nil {
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "There was an error retrieving the file, try again please.",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	defer file.Close()
	// Save the file with a random name, check if there already is a file with this name, create a record in the database and send that record to the user
	// Get the file ID
	rows, _ := db.DB.Query("SELECT id FROM files ORDER BY id DESC LIMIT 0, 1")
	defer rows.Close()
	rows.Next()
	var fid int64
	rows.Scan(&fid)
	fid++

	// Get the user ID
	rows, _ = db.DB.Query("SELECT id FROM users WHERE session_token = ?", cookie.Value)
	defer rows.Close()
	rows.Next()
	var uid int64
	rows.Scan(&uid)

	rows, _ = db.DB.Query("SELECT id FROM files WHERE filename = ?", handler.Filename)
	rows.Next()
	var _id int64
	rows.Scan(&_id)
	if _id != 0 {
		// File with this filename already exists
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "You already have a file with this name, please enter a different filename!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}


	// Check if the ServerName already exists
	uuid_ := createServerName()


	var f = database.File{
		ID: fid,
		Location: "/",
		Filename: handler.Filename,
		Public: public,
		Owner: uid,
		ServerName: uuid_.String(),
	}

	// Save the file on disk
	var buf bytes.Buffer
	io.Copy(&buf, file)
	ioutil.WriteFile("../files/" + f.ServerName, buf.Bytes(), 0644)
	buf.Reset()

	// Save the record to the database
	statement, _ := db.DB.Prepare("INSERT INTO files (id, location, filename, public, owner, server_name) VALUES (?, ?, ?, ?, ?, ?)")
	_, err = statement.Exec(f.ID, f.Location, f.Filename, f.Public, f.Owner, f.ServerName)
	defer statement.Close()

	if err != nil {
		fmt.Println(err)
	}

	json.NewEncoder(w).Encode(f)
}

func apiMeFilesGET(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, _ := r.Cookie("sessionToken")

	// User has already been authenticated with the `authenticate` middleware function
	// Get the UID
	rows, _ := db.DB.Query("SELECT id FROM users where session_token = ?", cookie.Value)
	rows.Next()
	var uid int64
	rows.Scan(&uid)
	defer rows.Close()

	rows, _ = db.DB.Query("SELECT * FROM files WHERE owner = ?", uid)
	defer rows.Close()

	var files []database.File

	for rows.Next() {
		var f database.File
		rows.Scan(&f.ID, &f.Location, &f.Filename, &f.Public, &f.Owner, &f.ServerName)
		files = append(files, f)
	}

	json.NewEncoder(w).Encode(files)
}

func apiPublicFilesGET(w http.ResponseWriter, r *http.Request) {
	// User has already been authenticated with the `authenticate` middleware function
	w.Header().Set("Content-Type", "application/json")

	rows, _ := db.DB.Query("SELECT * FROM files WHERE public = 1")

	defer rows.Close()

	var files []database.File

	for rows.Next() {
		var f database.File
		rows.Scan(&f.ID, &f.Location, &f.Filename, &f.Public, &f.Owner, &f.ServerName)
		files = append(files, f)
	}

	json.NewEncoder(w).Encode(files)
}

func apiFileGET(w http.ResponseWriter, r *http.Request) {
	// User has already been authenticated with the `authenticate` middleware function
	w.Header().Set("Content-Type", "application/json")

	cookie, _ := r.Cookie("sessionToken")

	// Get the UID
	rows, _ := db.DB.Query("SELECT id FROM users where session_token = ?", cookie.Value)
	rows.Next()
	var uid int64
	rows.Scan(&uid)
	defer rows.Close()

	params := r.URL.Query()

	// Check if the file GET parameter is set
	if len(params["file"][0]) < 1 {
		// GET parameter file is not set
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "You need to specify what file you want to request in the GET parameter!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	var serverName string = params["file"][0]
	rows, _ = db.DB.Query("SELECT * FROM files WHERE server_name = ? AND owner = ? OR public = 1", serverName, uid)
	defer rows.Close()
	rows.Next()

	var f database.File
	rows.Scan(&f.ID, &f.Location, &f.Filename, &f.Public, &f.Owner, &f.ServerName)

	// Check if the record exists
	if f.ID == 0 {
		// Record does not exist
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "The file you requested does not exist!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	// Record exists, read the file
	b, _ := ioutil.ReadFile("../files/" + f.ServerName)
	content := string(b)

	var res struct {
		ID         int64  `json:"id"`
		Location   string `json:"location"`
		Filename   string `json:"filename"`
		Public     bool   `json:"public"`
		Owner      int64  `json:"owner"`
		ServerName string `json:"serverName"`
		Content    string `json:"content"`
	}

	res.ID = f.ID
	res.Location = f.Location
	res.Filename = f.Filename
	res.Public = f.Public
	res.Owner = f.Owner
	res.ServerName = f.ServerName
	res.Content = content

	json.NewEncoder(w).Encode(res)
}

func apiRegisterPOST(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Username string `json:"username"`
		Email string `json:"email"`
		Password string `json:"password"`
		Secret string `json:"secret"`
	}

	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &body)

	s, _ := ioutil.ReadFile("../registerSecret")
	secret := string(s)

	if body.Secret != secret {
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "The secret you provided is wrong!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	// Secret is correct, continue registering
	// Check if username or email already exists
	rows, _ := db.DB.Query("SELECT id FROM users WHERE username = ? OR email = ?", body.Username, body.Email)
	defer rows.Close()
	rows.Next()
	var id int64
	rows.Scan(&id)

	if id != 0 {
		// Username or email already exists
		var res = httpRes{
			Success: false,
			Error: true,
			Message: "There already exists an account with that username or email address!",
		}
		json.NewEncoder(w).Encode(res)
		return
	}

	// All good, create an hash and save the user
	// Get the new ID
	rows, _ = db.DB.Query("SELECT id FROM users ORDER BY id DESC LIMIT 0, 1")
	defer rows.Close()
	rows.Next()
	var uid int64
	rows.Scan(&uid)
	uid++
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), 8)
	fmt.Println(len(hash))
	statement, _ := db.DB.Prepare("INSERT INTO users (id, username, email, hash, session_token, session_expires) VALUES (?, ?, ?, ?, '', 0)")
	_, _ = statement.Exec(uid, body.Username, body.Email, string(hash))
	defer statement.Close()

	// User saved
	var res = httpRes{
		Error: false,
		Success: true,
		Message: "You have successfully registered a user!",
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func apiFilesGET(w http.ResponseWriter, r *http.Request) {
	// User has already been authenticated with the `authenticate` middleware function
	w.Header().Set("Content-Type", "application/json")
	cookie, _ := r.Cookie("sessionToken")

	// Get the UID
	rows, _ := db.DB.Query("SELECT id FROM users where session_token = ?", cookie.Value)
	rows.Next()
	var uid int64
	rows.Scan(&uid)
	defer rows.Close()


	rows, _ = db.DB.Query("SELECT * FROM files WHERE owner = ? OR public = 1", uid)
	defer rows.Close()

	var files []database.File

	for rows.Next() {
		var f database.File
		rows.Scan(&f.ID, &f.Location, &f.Filename, &f.Public, &f.Owner, &f.ServerName)
		files = append(files, f)
	}

	json.NewEncoder(w).Encode(files)
}

func main() {
	setupCloseHandler()

	//e := sendMail2("joep@panictriggers.xyz", "Go test mail", "Dit\nis\neen\ntest\n!")
	//
	//if e != nil {
	//	panic(e)
	//}

	d, err := sql.Open("mysql",  "root:Test123@unix(/var/run/mysqld/mysqld.sock)/fs.panictriggers.xyz")
	if err != nil {
		panic(err)
	}
	db = database.NewDatabase(d)

	router := mux.NewRouter().StrictSlash(true)

	authenticatedRouter := router.PathPrefix("/").Subrouter()
	authenticatedRouter.Use(authenticateFE)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(logger)

	apiAuthenticatedRouter := router.PathPrefix("/api").Subrouter()
	apiAuthenticatedRouter.Use(authenticate)
	apiAuthenticatedRouter.Use(logger)

	apiRouter.HandleFunc("/", apiGET).Methods("GET")

	authenticatedRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	}).Methods("GET")

	authenticatedRouter.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/file/index.html")
	}).Methods("GET")

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/login/index.html")
	}).Methods("GET")

	apiRouter.HandleFunc("/login", apiLoginPOST).Methods("POST")
	apiRouter.HandleFunc("/register", apiRegisterPOST).Methods("POST")
	apiAuthenticatedRouter.HandleFunc("/me", apiMeGET).Methods("GET")
	apiAuthenticatedRouter.HandleFunc("/me/files", apiMeFilesGET).Methods("GET")
	apiAuthenticatedRouter.HandleFunc("/publicFiles", apiPublicFilesGET).Methods("GET")
	apiAuthenticatedRouter.HandleFunc("/files", apiFilesGET).Methods("GET")
	apiAuthenticatedRouter.HandleFunc("/file", apiFileGET).Methods("GET")
	apiAuthenticatedRouter.HandleFunc("/upload", apiUploadPOST).Methods("POST")

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	//router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//	http.ServeFile(w, r, "./static/index.html")
	//})

	log.Fatal(http.ListenAndServe(":80", router))
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
	s1, _ := db.DB.Prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, location VARCHAR(512), filename VARCHAR(512), public BOOLEAN, owner INTEGER, server_name VARCHAR(128))")
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

func setupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C has been pressed, closing the program")
		db.DB.Close()
		os.Exit(0)
	}()
}
