package database

type User struct {
	ID             uint   `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Hash           string `json:"-"`
	SessionToken   string `json:"sessionToken"`
	SessionExpires int64 `json:"sessionExpires"`
}