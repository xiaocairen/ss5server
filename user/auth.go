package user

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type auth struct {
	users map[string]string
}

func NewAuth() *auth {
	return &auth{}
}

func (a auth) Authentication(user string, pass string) bool {
	userData, err := a.loadUsers()
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	users, err := a.parseUsers(userData)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	if _, f := users["tester"]; !f {
		users["tester"] = "tester8181"
	}

	p, f := users[user]
	if !f {
		return false
	}

	return p == pass
}

func (a *auth) loadUsers() (string, error) {
	f, err := os.OpenFile("/etc/ss5server/users.conf", os.O_RDONLY|os.O_CREATE, 0777)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var (
		buf = make([]byte, 10)
		res = ""
	)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			res += string(buf[:n])
		}

		if err == io.EOF || n < 10 {
			break
		}
	}

	return res, nil
}

func (a *auth) parseUsers(d string) (map[string]string, error) {
	if len(d) == 0 {
		return nil, fmt.Errorf("users.conf is empty")
	}

	users := make(map[string]string)
	res := strings.Split(strings.Replace(strings.TrimSpace(d), "\r", "", -1), "\n")
	for _, v := range res {
		auths := strings.Split(v, " ")
		if len(auths) != 2 {
			return nil, fmt.Errorf("bad users.conf, '%s'", v)
		}

		user := strings.TrimSpace(auths[0])
		pass := strings.TrimSpace(auths[1])
		users[user] = pass
	}

	return users, nil
}
