/*

rtop - the remote system monitoring utility

Copyright (c) 2015 RapidLoop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package main

import (

	"encoding/json"
	"gopkg.in/yaml.v2"

	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

const VERSION = "1.0"
const DEFAULT_REFRESH = 5 // default refresh interval in seconds

var currentUser *user.User

//----------------------------------------------------------------------------
// Command-line processing

func usage(code int) {
	fmt.Printf(
		`rtop %s - (c) 2015 RapidLoop - MIT Licensed - http://rtop-monitor.org
rtop monitors server statistics over an ssh connection

Usage: rtop [-i private-key-file] [-t interval] [-n namedCollection] [user@]host[:port]

	-i private-key-file
		PEM-encoded private key file to use (default: ~/.ssh/id_rsa if present)
	[user@]host[:port]
		the SSH server to connect to, with optional username and port
	-t interval
		refresh interval in seconds (default: %d)
	-n namedCollection
		collect a single named checkpoint collection instead of continuous collections

`, VERSION, DEFAULT_REFRESH)
	os.Exit(code)
}

func shift(q []string) (ok bool, val string, qnew []string) {
	if len(q) > 0 {
		ok = true
		val = q[0]
		qnew = q[1:]
	}
	return
}

func parseCmdLine() (hosts []Section, interval time.Duration, bootstrap bool, onlyBootstrap bool, namedCollection string, testFile string) {
	ok, arg, args := shift(os.Args)
	var argKey,  argInt string
	bootstrap = false
	onlyBootstrap = false
	namedCollection = "NOT_A_NAMED_COLLECTION"
	testFile = "NO_TEST_FILE"
	var hostStrings []string
	for ok {
		ok, arg, args = shift(args)
		if !ok {
			break
		}
		if arg == "-h" || arg == "--help" || arg == "--version" {
			usage(0)
		}
		if arg == "-i" {
			ok, argKey, args = shift(args)
			if !ok {
				usage(1)
			}
		} else if arg == "-b" {
			bootstrap = true
		} else if arg == "-B" {
			bootstrap = true
			onlyBootstrap = true
		} else if arg == "-t" {
			argInt = arg
		} else if arg == "-n" {
			ok, namedCollection, args = shift(args)
			if !ok {
				usage(1)
			}
		} else if arg == "-f" {
			ok, testFile, args = shift(args)
			if !ok {
				usage(1)
			}
		} else {
			hostStrings = append(hostStrings, arg)
		}
	}
	if len(hostStrings) == 0 {
		usage(1)
	}

	var key string
	// key
	if len(argKey) != 0 {
		key = argKey
	} // else key remains ""
	if bootstrap {
		key = "bootstrap.key"
	}

	for _, argHost := range hostStrings {
		var addr string
		var username string
		var host string
		var port int
		if i := strings.Index(argHost, "@"); i != -1 {
			username = argHost[:i]
			if i+1 >= len(argHost) {
				usage(1)
			}
			addr = argHost[i+1:]
		} else {
			// username remains ""
			addr = argHost
		}

		// addr -> host, port
		if p := strings.Split(addr, ":"); len(p) == 2 {
			host = p[0]
			var err error
			if port, err = strconv.Atoi(p[1]); err != nil {
				log.Printf("bad port: %v", err)
				usage(1)
			}
			if port <= 0 || port >= 65536 {
				log.Printf("bad port: %d", port)
				usage(1)
			}
		} else {
			host = addr
			// port remains 0
		}

		// get current user
		var err error
		currentUser, err = user.Current()
		if err != nil {
			log.Print(err)
			return
		}

		// fill from ~/.ssh/config if possible
		sshConfig := filepath.Join(currentUser.HomeDir, ".ssh", "config")
		if _, err := os.Stat(sshConfig); err == nil {
			if parseSshConfig(sshConfig) {
				shost, sport, suser, skey := getSshEntry(host)
				if len(shost) > 0 {
					host = shost
				}
				if sport != 0 && port == 0 {
					port = sport
				}
				if len(suser) > 0 && len(username) == 0 {
					username = suser
				}
				if len(skey) > 0 && len(key) == 0 {
					key = skey
				}
				// log.Printf("after sshconfig: %s %d %s %s", host, port, username, key)
			}
		}

		// fill in still-unknown ones with defaults
		if port == 0 {
			port = 22
		}
		if len(username) == 0 {
			username = currentUser.Username
		}
		if len(key) == 0 {
			idrsap := filepath.Join(currentUser.HomeDir, ".ssh", "id_rsa")
			if _, err := os.Stat(idrsap); err == nil {
				key = idrsap
			}
		}
		hosts = append(hosts, Section{ host, port, username, key })
	}

	// interval
	if len(argInt) > 0 {
		i, err := strconv.ParseUint(argInt, 10, 64)
		if err != nil {
			log.Printf("bad interval: %v", err)
			usage(1)
		}
		if i <= 0 {
			log.Printf("bad interval: %d", i)
			usage(1)
		}
		interval = time.Duration(i) * time.Second
	} // else interval remains 0

	return
}

//----------------------------------------------------------------------------

func main() {

	log.SetPrefix("rtop: ")
	log.SetFlags(0)

	// get params from command line
	hosts, interval, bootstrap, onlyBootstrap, namedCollection, testFile := parseCmdLine()
	// log.Printf("cmdline: %s %d %s %s", host, port, username, key)
	if interval == 0 {
		interval = DEFAULT_REFRESH * time.Second
	}
	// log.Printf("after defaults: %s %d %s %s", host, port, username, key)
	// log.Printf("interval: %v", interval)

	if bootstrap {
		var privateKeyString string
		if _, err := os.Stat("bootstrap.key"); os.IsNotExist(err) {
			if _, err := os.Stat("bootstrap.key.pub"); os.IsNotExist(err) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					fmt.Printf("Bootstrapping failed: %s\n", err);
					os.Exit(1)
				}
				privateKeyFile, err := os.Create("bootstrap.key")
				defer privateKeyFile.Close()
				if err != nil {
					fmt.Printf("Bootstrapping failed: %s\n", err);
					os.Exit(1)
				}
				privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
				if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
					fmt.Printf("Bootstrapping failed: %s\n", err);
					os.Exit(1)
				}
				pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
				if err != nil {
					fmt.Printf("Bootstrapping failed: %s\n", err);
					os.Exit(1)
				}
				privateKeyBin := ssh.MarshalAuthorizedKey(pub)
				ioutil.WriteFile("bootstrap.key.pub", privateKeyBin, 0655)
				privateKeyString = fmt.Sprintf("%s", privateKeyBin)
			} else {
				fmt.Println("bootstrap.key.pub exists but bootstrap.key does not exist. Either put bootstrap.key back or clean up bootstrap.key.pub and rerun bootstrap")
				os.Exit(1)
			}
		} else {
			if _, err := os.Stat("bootstrap.key.pub"); os.IsNotExist(err) {
				fmt.Println("bootstrap.key exists but bootstrap.key.pubdoes not exist. Either put bootstrap.key back or clean up bootstrap.key.pub and rerun bootstrap")
				os.Exit(1)
			} else {
				privateKeyBin, err := ioutil.ReadFile("bootstrap.key.pub")
				if err != nil {
					fmt.Printf("bootstrap.key.pub could not be read: %s", err)
					os.Exit(1)
				}
				privateKeyString = fmt.Sprintf("%s", privateKeyBin)
			}
		}

		for _, host := range hosts {
			bootstrapper(host, privateKeyString)
			host.IdentityFile = "bootstrap.key"
		}
		if onlyBootstrap {
			os.Exit(0)
		}
	}

	if _, err := os.Stat("timeSeries"); os.IsNotExist(err) {
		err := os.Mkdir("timeSeries", 0755)
		if err != nil {
			fmt.Printf("Error creating timeSeries directory: %s", err)
		}
	}

	var dataCollectors []DataCollector
	if testFile != "NO_TEST_FILE" {

		yamlFile, err := ioutil.ReadFile(testFile)
		if err != nil {
			fmt.Printf("ERROR cannot read yaml file: %s\n", err)
			os.Exit(1)
		}
		err = yaml.Unmarshal(yamlFile, &dataCollectors)
		if err != nil {
			fmt.Printf("ERROR cannot unmarshal yaml: %s\n", err)
			os.Exit(1)
		}
	} else {
		dataCollectors = make([]DataCollector, 0)
	}

	if namedCollection != "NOT_A_NAMED_COLLECTION" {
		if _, err := os.Stat("collections"); os.IsNotExist(err) {
			err := os.Mkdir("collections", 0755)
			if err != nil {
				fmt.Printf("Error creating timeSeries directory: %s", err)
			}
		}
		for _, host := range hosts {
			//TODO make this parallellized with a sync.WaitGroup
			singleCollection(host, dataCollectors, namedCollection)
		}
		os.Exit(0)
	}

	for _, host := range hosts {
		go mainLoop(host, interval, dataCollectors)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	<-sig
}

func bootstrapper( host Section, privateKeyString string ) {
	addr := fmt.Sprintf("%s:%d", host.Hostname, host.Port)
	client := sshConnect(host.User, addr, host.IdentityFile)
	if client == nil {
		fmt.Printf("Could not bootstrap %s", addr)
		return
	}
	_, err := runCommand(client, fmt.Sprintf("grep \"%s\" ~/.ssh/authorized_keys", strings.TrimSuffix(privateKeyString, "\n")))
	if err != nil {
		fmt.Printf("\nAdding authorized key to %s from bootstrap.key.pub\n", addr)
		_, err := runCommand(client, "mkdir -p ~/.ssh")
		if err != nil {
			fmt.Printf("mkdir -p ~/.ssh failed on %s: %s\n", addr, err)
		}
		_, err = runCommand(client, fmt.Sprintf("echo \"%s\" >> ~/.ssh/authorized_keys", privateKeyString))
		if err != nil {
			fmt.Printf("Adding authorized key failed on %s: %s", addr, err)
		}
	}
	client.Close()
}

//TODO add returning of an error for better error handling
func singleCollection( host Section, dataCollectors []DataCollector, name string) {
	addr := fmt.Sprintf("%s:%d", host.Hostname, host.Port)
	client := sshConnect(host.User, addr, host.IdentityFile)
	if client == nil {
		fmt.Println("Connection failed")
		return
	}

	stats := Stats{}
	stats.Time = time.Now()
	stats.Name = name
	stats.Collections = make(map[string]interface{})
	err := getAllStats(client, &stats, dataCollectors)
	if err != nil {
		return
	}
	file, err := json.MarshalIndent(stats, "", " ")
	if err != nil {
		return
	}
	err = ioutil.WriteFile(fmt.Sprintf("collections/%s-%s.json", name, host.Hostname), file, 0644)
	if err != nil {
		return
	}
}

func mainLoop( host Section, interval time.Duration, dataCollectors []DataCollector ) {
	addr := fmt.Sprintf("%s:%d", host.Hostname, host.Port)
	mainLoopDone := false
	for !mainLoopDone {
		fmt.Println("mainLoop")
		nanoSeconds := time.Now().String()
		fmt.Printf("time: %v\n", string(nanoSeconds))
		client := sshConnect(host.User, addr, host.IdentityFile)
		if client == nil {
			fmt.Println("Connection failed")
			time.Sleep(15 * time.Second)
			continue
		}

		tsDir := fmt.Sprintf("timeSeries/%s", host.Hostname)
		if _, err := os.Stat(tsDir); os.IsNotExist(err) {
			err := os.Mkdir(tsDir, 0755)
			if err != nil {
				fmt.Printf("Error creating timeSeries directory: %s", err)
			}
		}
		output := getOutput()
		// the loop
		//showStats(output, client, dbclient, host)
		timer := time.Tick(interval)
		done := false
		for !done {
			<-timer
			nanoSeconds = time.Now().String()
			fmt.Printf("time: %v\n", string(nanoSeconds))
			err := showStats(output, client, host.Hostname, dataCollectors)
			if err != nil {
				done = true
				fmt.Printf("show Stats Error  %s: %s\n", host.Hostname, err)
			}
			nanoSeconds = time.Now().String()
			fmt.Printf("time: %v\n", string(nanoSeconds))
			fmt.Println("showStatsLoop")
		}
	}
}

func showStats(output io.Writer, client *ssh.Client, host string, dataCollectors []DataCollector) error {
	stats := Stats{}
	stats.Time = time.Now()
	stats.Name = strconv.FormatInt(stats.Time.Unix(), 10)
	stats.Collections = make(map[string]interface{})
	err := getAllStats(client, &stats, dataCollectors)
	if err != nil {
		return err
	}
	file, err := json.MarshalIndent(stats, "", " ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fmt.Sprintf("timeSeries/%s/%d.json", host, stats.Time.Unix()), file, 0644)
	if err != nil {
		return err
	}
	//used := stats.MemTotal - stats.MemFree - stats.MemBuffers - stats.MemCached
	return nil
}

const (
	escClear   = "\033[H\033[2J"
	escRed     = "\033[31m"
	escReset   = "\033[0m"
	escBrightWhite = "\033[37;1m"
)
