package database

type File struct {
	ID         uint   `json:"id"`
	Location   string `json:"location"`
	Filename   string `json:"filename"`
	Public     bool   `json:"public"`
	Owner      uint   `json:"owner"`
	ServerName string `json:"serverName"`
}
