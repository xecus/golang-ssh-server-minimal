package main

import (
	"io"
	"io/ioutil"
	"log"
	b64 "encoding/base64"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func main() {

	ssh.Handle(func(s ssh.Session) {

		user := s.User()
		keyType := s.PublicKey().Type()
		addr := s.RemoteAddr()
		publicKeyString := keyType + " " + b64.StdEncoding.EncodeToString(s.PublicKey().Marshal())

		io.WriteString(s, "<Session Information>\n")
		io.WriteString(s, "Hello "+user+" "+addr.String()+" \n")
		io.WriteString(s, "your publicKey:\n")
		io.WriteString(s, publicKeyString+"\n")

		io.WriteString(s, "<Environments>\n")
		for _, s2 := range(s.Environ()) {
			io.WriteString(s, s2 + "\n")
		}

		io.WriteString(s, "<Sent Command>\n")
		for _, s2 := range(s.Command()) {
			io.WriteString(s, s2 + "\n")
		}

	})

	publicKeyHandler := ssh.PublicKeyAuth(func(user string, key ssh.PublicKey) bool {

		data, err := ioutil.ReadFile("id_rsa.pub")
		if err != nil {
			log.Fatal("Error: ioutil.ReadFile")
		}

		allowed, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			log.Fatal("Error: ssh.ParseAuthorizedKey")
		}

		log.Println("user", user)
		log.Println("key", gossh.FingerprintLegacyMD5(key))
		log.Println("allowed", allowed)

		return user == "admin" && ssh.KeysEqual(key, allowed)
	})

	log.Fatal(ssh.ListenAndServe(":2222", nil, publicKeyHandler))

}
