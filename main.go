// 參考來源 - https://www.jianshu.com/p/7d315f8551ad
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config -
type Config struct {
	Groups     []Group `json:"groups"`
	Account    string  `json:"account"`
	Password   string  `json:"password"`
	Sshkeypath string  `json:"sshkeypath"`
}

// Group -
type Group struct {
	Account    string   `json:"account"`
	Password   string   `json:"password"`
	Sshkeypath string   `json:"sshkeypath"`
	Hosts      []string `json:"hosts"`
	Shells     []string `json:"shells"`
}

func main() {

	// Open our jsonFile
	jsonFile, err := os.Open("./ezible.json")
	if err != nil {
		failed(err)
		return
	}
	success("Successfully Opened ezible.json")
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		failed(err)
		return
	}

	var config Config

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		failed(err)
		return
	}

	var wg sync.WaitGroup

	for i := 0; i < len(config.Groups); i++ {
		group := config.Groups[i]
		for j := 0; j < len(group.Hosts); j++ {
			host := group.Hosts[j]
			wg.Add(1)
			go func(wg *sync.WaitGroup, i int) {
				defer wg.Done()
				account := config.Account
				if group.Account != "" {
					account = group.Account
				}

				password := config.Password
				if group.Password != "" {
					password = group.Password
				}

				sshkeypath := config.Sshkeypath
				if group.Sshkeypath != "" {
					sshkeypath = group.Sshkeypath
				}
				session, err := connect(account, password, host, sshkeypath, 22, []string{})
				// session, err := connect("rdcy4168", "qwe123", "192.168.4.130", "/Users/jerry/.ssh/id_rsa", 22, []string{})
				if err != nil {
					failed(err)
					return
				}
				defer session.Close()

				cmdlist := []string{}
				cmdlist = append(group.Shells, "exit")
				// cmdlist := []string{"pwd","exit"}
				stdinBuf, err := session.StdinPipe()
				if err != nil {
					failed(err)
					return
				}

				var outbt, errbt bytes.Buffer
				session.Stdout = &outbt
				session.Stderr = &errbt

				// session.Run("pwd")
				err = session.Shell()
				if err != nil {
					failed(err)
					return
				}

				for _, c := range cmdlist {
					c = c + "\n"
					stdinBuf.Write([]byte(c))
				}

				session.Wait()
				success("group" + strconv.Itoa(i) + " >>>>>> " + host + " Start \n")
				fmt.Println((outbt.String() + errbt.String()))
				// fmt.Println(session.Stdout)
				success("group" + strconv.Itoa(i) + " <<<<<< " + host + " End")
			}(&wg, i)
		}
	}

	wg.Wait()
	// select {}
}

func connect(user, password, host, key string, port int, cipherList []string) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	if key == "" {
		auth = append(auth, ssh.Password(password))
	} else {
		pemBytes, err := ioutil.ReadFile(key)
		if err != nil {
			return nil, err
		}

		var signer ssh.Signer
		if password == "" {
			signer, err = ssh.ParsePrivateKey(pemBytes)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(password))
		}
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(cipherList) == 0 {
		config = ssh.Config{
			Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
		}
	} else {
		config = ssh.Config{
			Ciphers: cipherList,
		}
	}

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		Config:  config,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return nil, err
	}

	return session, nil
}

func success(s string) {
	fmt.Println("\u001b[35m[Ezible]\u001b\u001b[32m[Success]\u001b[0m", "\u001b[36m"+s+"\u001b[0m")
}

func failed(err error) {
	fmt.Println("\u001b[35m[Ezible]\u001b\u001b[31m[Failed]\u001b[0m", "\u001b[36m"+err.Error()+"\u001b[0m")
}
