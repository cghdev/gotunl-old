package gotunl

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type profile struct {
	Path string
	ID   int
	Conf string
}
type Gotunl struct {
	authKey  string
	profPath string
	service  string
	Profiles map[string]profile
}

func _getKey() string {
	keyPath := "/Applications/Pritunl.app/Contents/Resources/auth"
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Fatal(err)
		}
		return string(key)
	}
	return ""
}

func _getProfilePath() string {
	home := os.Getenv("HOME")
	profPath := home + "/Library/Application Support/pritunl/profiles"
	if _, err := os.Stat(profPath); !os.IsNotExist(err) {
		return profPath
	}
	return ""
}

func New() *Gotunl {
	g := Gotunl{_getKey(), _getProfilePath(), "http://localhost:9770/", map[string]profile{}}
	g.loadProfiles()
	return &g
}

func (g Gotunl) makeReq(verb string, endpoint string, data string) string {
	url := g.service + endpoint
	req, err := http.NewRequest(verb, url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "pritunl")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", g.authKey)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode == 200 {
		body, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return string(body)
	}
	return string(res.StatusCode)

}

func (g Gotunl) CheckStatus() string {
	s := g.makeReq("GET", "status", "")
	return gjson.Get(s, "status").String()
}

func (g Gotunl) Ping() bool {
	p := g.makeReq("GET", "ping", "")
	if p == "" {
		return true
	}
	return false
}

func (g Gotunl) GetConnections() string {
	cons := g.makeReq("GET", "profile", "")
	return cons
}

func (g Gotunl) StopConnections() {
	g.makeReq("POST", "stop", "")
}

func (g Gotunl) loadProfiles() {
	res, _ := filepath.Glob(g.profPath + "/*.conf")
	for i, f := range res {
		c := i + 1
		prof := strings.Split(filepath.Base(f), ".")[0]
		conf, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		config := string(conf)                        // keep the whole config file to use later, instead of reading the file again.
		if gjson.Get(config, "name").String() == "" { // If "name": null it will set the name automatically.
			user := gjson.Get(config, "user").String()
			server := gjson.Get(config, "server").String()
			config, _ = sjson.Set(config, "name", fmt.Sprintf("%v (%v)", user, server))
		}
		g.Profiles[prof] = profile{f, c, config}
	}
}

func (g Gotunl) GetProfile(id string) (string, string) {
	auth := ""
	g.loadProfiles()
	prof := g.Profiles[id]
	ovpnFile := strings.Replace(prof.Path, ".conf", ".ovpn", 1)
	ovpn, err := ioutil.ReadFile(ovpnFile)
	if err != nil {
		log.Fatal(err)
	}
	for _, l := range strings.Split(string(ovpn), "\n") {
		if strings.Contains(l, "auth-user-pass") && len(l) <= 17 { //check if it needs credentials and they are not provided as parameter
			auth = "creds"
		}
	}
	mode := gjson.Get(prof.Conf, "password_mode").String()
	if auth != "" && strings.Contains(prof.Conf, "password_mode") && mode != "" {
		auth = mode
	}
	command := "security find-generic-password -w -s pritunl -a " + id
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		log.Fatal(err)
	}
	res, err := b64.StdEncoding.DecodeString(string(out))
	if err != nil {
		log.Fatal(err)
	}
	vpn := string(ovpn) + "\n" + string(res)
	return vpn, auth

}

func (g Gotunl) ConnectProfile(id string, user string, password string) {
	data := fmt.Sprintf(`{"id": "%v", "reconnect": true, "timeout": true}`, id)
	ovpn, auth := g.GetProfile(id)
	if auth != "" {
		if auth[len(auth)-3:] == "pin" {
			var otp string
			user = "pritunl"
			if password == "" {
				fmt.Printf("Enter the PIN: ")
				pass, err := gopass.GetPasswdMasked()
				if err != nil {
					log.Fatal(err)
				}
				if auth == "otp_pin" {
					fmt.Printf("Enter the OTP code: ")
					fmt.Scanln(&otp)
				}
				password = string(pass) + otp
			}
		}
		if user == "" {
			fmt.Printf("Enter the username: ")
			fmt.Scanln(&user)

		}
		if password == "" {
			fmt.Printf("Enter the password: ")
			pass, _ := gopass.GetPasswdMasked()
			password = string(pass)
		}
		data, _ = sjson.Set(data, "username", user)
		data, _ = sjson.Set(data, "password", password)
	}
	data, _ = sjson.Set(data, "data", ovpn)
	g.makeReq("POST", "profile", data)
}

func (g Gotunl) DisconnectProfile(id string) {
	g.makeReq("DELETE", "profile", `{"id": "`+id+`"}`)
}
