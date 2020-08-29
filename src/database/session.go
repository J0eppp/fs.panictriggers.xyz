package database

import (
	"fmt"
	uuid "github.com/satori/go.uuid"
	"time"
)

type Session struct {
	SessionToken string `json:"sessionToken"`
	SessionExpires int64 `json:"sessionExpires"`
}

func NewSession() Session{
	token, _ := uuid.NewV4()
	fmt.Println(time.Now().Unix())
	fmt.Println(time.Now().Add(time.Hour * time.Duration(24)).Unix())
	return Session{
		SessionToken: token.String(),
		//SessionExpires: time.Now().Unix() + 60 * 60 * 24, // Session token will be valid for one day
		SessionExpires: time.Now().Add(time.Hour * time.Duration(24)).Unix(),
	}
}