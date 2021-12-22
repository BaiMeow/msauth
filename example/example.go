package main

import (
	"github.com/BaiMeow/msauth"
	"github.com/Tnze/go-mc/bot"
	"log"
)

func main() {
	msauth.SetClient("你的clientID", "")
	profile, astk, err := msauth.Login()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(profile, astk)

	//推荐和go-mc一起使用
	c := bot.NewClient()
	c.Auth.UUID = profile.Id
	c.Auth.Name = profile.Name
	c.Auth.AsTk = astk
	if err := c.JoinServer("localhost"); err != nil {
		log.Fatal(err)
	}
	if err := c.HandleGame(); err != nil {
		log.Fatal(err)
	}
}
