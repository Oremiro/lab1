package main

import (
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"sync"
)

var (
	mu           sync.Mutex
	usersDB      = make(map[string]string)
	sessions     = make(map[string]string)
	superUser    = "admin"
	superUserKey = "admin"
	sessionKey   = "session-name"
)

func main() {
	usersDB[superUser] = superUserKey

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/register", registerHandler)

	// Initial superuser registration
	registerUser(superUser, "admin")

	fmt.Println("Server is listening on :8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "home", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if isValidUser(username, password) {
			sessionID := generateSessionID()
			sessions[sessionID] = username

			http.SetCookie(w, &http.Cookie{
				Name:  sessionKey,
				Value: sessionID,
			})

			if username == superUser {
				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	renderTemplate(w, "home", "Invalid credentials")
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	if username != "" {
		renderTemplate(w, "dashboard", username)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	if username == superUser {
		renderTemplate(w, "admin", username)
		return
	}
	
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		registerUser(username, password)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "register", nil)
}

func isValidUser(username, password string) bool {
	mu.Lock()
	defer mu.Unlock()

	storedPassword, exists := usersDB[username]
	return exists && storedPassword == password
}

func registerUser(username, password string) {
	mu.Lock()
	defer mu.Unlock()

	usersDB[username] = password
}

func getUsernameFromSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionKey)
	if err != nil {
		return ""
	}

	return sessions[cookie.Value]
}

func generateSessionID() string {
	return fmt.Sprintf("%d", rand.Intn(1000000))
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplFiles := fmt.Sprintf("templates/%s.html", tmpl)
	t, err := template.ParseFiles(tmplFiles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
