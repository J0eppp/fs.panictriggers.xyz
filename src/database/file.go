package database

type File struct {
	ID         int64  `json:"id"`
	Location   string `json:"location"`
	Filename   string `json:"filename"`
	Public     bool   `json:"public"`
	Owner      int64  `json:"owner"`
	ServerName string `json:"serverName"`
}
