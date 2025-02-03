package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cli/oauth/device"
	"github.com/gliderlabs/ssh"
	"golang.org/x/term"

	"abap34-server/internal/db"
	"abap34-server/internal/util"
)

const (
	MESSAGE_LOAD_COUNT = 15
)

type ChatSession struct {
	Session        ssh.Session
	Term           *term.Terminal
	Prompt         string
	Username       string
	CurrentChannel string
}

func (cs *ChatSession) Write(msg string) {
	cs.Term.Write([]byte(msg))
}

func (cs *ChatSession) Writeln(msg string) {
	cs.Write(msg + "\n")
}

func authenticateViaPublicKey(s ssh.Session, pk ssh.PublicKey) error {
	username := s.User()
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to retrieve GitHub public keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to retrieve keys, status: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading keys: %v", err)
	}
	keysStr := string(data)
	lines := strings.Split(keysStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if ssh.KeysEqual(pk, authorizedKey) {
			return nil
		}
	}
	return fmt.Errorf("no matching public key found for GitHub user %s", username)
}

func authenticateGitHub(cs *ChatSession) error {
	cs.Writeln("GitHub authentication is required. Press Enter to begin.")
	_, err := cs.Term.ReadLine()
	if err != nil {
		cs.Writeln("Error reading input: " + err.Error())
		return err
	}

	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		cs.Writeln("GITHUB_CLIENT_ID environment variable is not set.")
		return fmt.Errorf("GITHUB_CLIENT_ID not set")
	}

	httpClient := http.DefaultClient
	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, []string{"read:user"})
	if err != nil {
		cs.Writeln("Error initiating device flow: " + err.Error())
		return err
	}

	cs.Writeln("Visit " + code.VerificationURI + " and enter the code " + code.UserCode)

	accessToken, err := device.Wait(context.TODO(),
		httpClient, "https://github.com/login/oauth/access_token",
		device.WaitOptions{
			ClientID:   clientID,
			DeviceCode: code,
		})

	if err != nil {
		cs.Writeln("Error waiting for device flow: " + err.Error())
	}

	githubUser, err := fetchGitHubUser(accessToken.Token)
	if err != nil {
		cs.Writeln("Failed to fetch GitHub user info: " + err.Error())
		return err
	}

	cs.Username = githubUser
	cs.Writeln("Authentication successful! You are logged in as " + util.Colorize(cs.Username))
	cs.Writeln(util.Boldstring("Hint: You can pass your public which registered in GitHub to authenticate directly and skip this step. next time. details: https://github.com/abap34/server.abap34.com/blob/main/README.md#login"))
	return nil
}

func fetchGitHubUser(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "token "+accessToken)
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var data struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Login, nil
}

func (cs *ChatSession) JoinChannel(channel string) {
	if cs.CurrentChannel != "" {
		cs.LeaveChannel()
	}
	channelsMutex.Lock()
	if channels[channel] == nil {
		channels[channel] = make(map[*ChatSession]bool)
	}
	channels[channel][cs] = true
	channelsMutex.Unlock()
	cs.CurrentChannel = channel
	cs.Writeln("Joined channel [" + channel + "]")
	messages, err := db.LoadMessages(channel, MESSAGE_LOAD_COUNT)
	if err != nil {
		cs.Writeln("Error loading history: " + err.Error())
	} else if len(messages) > 0 {
		cs.Writeln("Last messages in [" + channel + "]:")
		for _, m := range messages {
			cs.Writeln("  " + m)
		}
	}
	broadcastMessage(channel, fmt.Sprintf("*** %s has joined ***", util.Colorize(cs.Username)), cs)
	log.Printf("User '%s' joined channel '%s'", cs.Username, channel)
}

// MEMO: may be removed
func (cs *ChatSession) LeaveChannel() {
	if cs.CurrentChannel == "" {
		cs.Writeln("You are not in any channel.")
		return
	}
	channelsMutex.Lock()
	if sessMap, ok := channels[cs.CurrentChannel]; ok {
		delete(sessMap, cs)
		if len(sessMap) == 0 {
			delete(channels, cs.CurrentChannel)
		}
	}
	channelsMutex.Unlock()
	broadcastMessage(cs.CurrentChannel, fmt.Sprintf("*** %s has left ***", util.Colorize(cs.Username)), cs)
	cs.Writeln("Left channel [" + cs.CurrentChannel + "]")
	cs.CurrentChannel = ""
}

func (cs *ChatSession) PrintHelp() {
	cs.Writeln("Available commands:")
	cs.Writeln("  /help                - Show this help message")
	cs.Writeln("  /join <channel>      - Join a channel")
	cs.Writeln("  /leave               - Leave the current channel")
	cs.Writeln("  /channels            - List active channels")
	cs.Writeln("  /users               - List users")
	cs.Writeln("  /tp <user>           - Teleport to a user")
	cs.Writeln("  /msg <user> <msg>    - Send a private message")
	cs.Writeln("  /history <count>     - Show last <count> messages")
	cs.Writeln("  /quit                - Quit the session")
}

func (cs *ChatSession) ListChannels() {
	cs.Writeln("All channels:")
	channelsMutex.Lock()
	for channel := range channels {
		users := []string{}
		for sess := range channels[channel] {
			users = append(users, sess.Username)
		}
		cs.Writeln("  " + channel + " (" + strings.Join(users, ", ") + ")")
	}
	channelsMutex.Unlock()

}

func (cs *ChatSession) ListUsers() {
	cs.Writeln("Active users:")
	sessionsMutex.Lock()
	for name := range sessions {
		cs.Writeln("  " + name + " at " + sessions[name].CurrentChannel)
	}
	sessionsMutex.Unlock()
}

func (cs *ChatSession) PrivateMessage(target, message string) {
	sessionsMutex.Lock()
	recipient, ok := sessions[target]
	sessionsMutex.Unlock()
	if !ok {
		cs.Writeln("User " + target + " not found.")
		return
	}
	db.SaveMessage("", cs.Username, fmt.Sprintf("[Private] %s: %s", cs.Username, message))
	recipient.Write("\r\033[K")
	recipient.Writeln(fmt.Sprintf("[Private] %s: %s", util.Colorize(cs.Username), message))
	recipient.Write(recipient.Prompt)
	cs.Write("\r\033[K")
	cs.Writeln(fmt.Sprintf("[Private] to %s: %s", target, message))
	cs.Write(cs.Prompt)
}

func (cs *ChatSession) Teleport(target string) {
	sessionsMutex.Lock()
	recipient, ok := sessions[target]
	sessionsMutex.Unlock()
	if !ok {
		cs.Writeln("User " + target + " not found.")
		return
	}
	recipient.CurrentChannel = cs.CurrentChannel
	cs.Writeln("Teleported to " + target)
}

func (cs *ChatSession) History(count int) {
	if cs.CurrentChannel == "" {
		cs.Writeln("Please join a channel using /join <channel> first.")
		return
	}
	messages, err := db.LoadMessages(cs.CurrentChannel, count)
	if err != nil {
		cs.Writeln("Error loading history: " + err.Error())
	} else if len(messages) > 0 {
		cs.Writeln("Last messages in [" + cs.CurrentChannel + "]:")
		for _, m := range messages {
			cs.Writeln("  " + m)
		}
	}
}

func HandleSession(s ssh.Session) {		
	// Try public key authentication first
	authPassed := false

	if pk := s.PublicKey(); pk != nil {
		err := authenticateViaPublicKey(s, pk)
		if err != nil {
			s.Write([]byte("Public key authentication not passed. Please authenticate with GitHub.\n"))
		} else {
			authPassed = true
		}
	}

	_, _, isPty := s.Pty()

	if !isPty {
		s.Write([]byte("This session requires a PTY. Please connect with a terminal.\n"))
		s.Exit(1)
		return
	}
	
	term := term.NewTerminal(s, "> ")
	cs := &ChatSession{
		Session:  s,
		Term:     term,
		Prompt:   "> ",
		Username: s.User(), 
	}



	if !authPassed {
		if err := authenticateGitHub(cs); err != nil {
			cs.Writeln("GitHub authentication failed. Exiting.")
			s.Exit(1)
			return
		}
	}


	RegisterSession(cs)
	cs.Writeln(util.Boldstring(util.Colorize("==== Welcome to abap34's chat server! ====")))
	cs.Writeln("└ Your username is: " + util.Colorize(cs.Username))
	cs.Writeln("")
	cs.PrintHelp()
	cs.Writeln("")

	// User add to general channel by default
	cs.JoinChannel("general")

	for {
		line, err := cs.Term.ReadLine()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			// Skip empty lines
			continue
		}
		if strings.HasPrefix(line, "/") {
			args := strings.SplitN(line, " ", 3)
			switch args[0] {
			case "/help":
				cs.PrintHelp()
			case "/join":
				if len(args) < 2 {
					cs.Writeln("Usage: /join <channel>")
				} else {
					cs.JoinChannel(args[1])
				}
			case "/leave":
				cs.LeaveChannel()
			case "/channels":
				cs.ListChannels()
			case "/users":
				cs.ListUsers()
			case "/tp":
				if len(args) < 2 {
					cs.Writeln("Usage: /tp <user>")
				} else {
					cs.Teleport(args[1])
				}
			case "/msg":
				if len(args) < 3 {
					cs.Writeln("Usage: /msg <user> <message>")
				} else {
					cs.PrivateMessage(args[1], args[2])
				}
			case "/history":
				if len(args) < 2 {
					cs.Writeln("Usage: /history <count>")
				} else {
					count := MESSAGE_LOAD_COUNT
					if n, err := strconv.Atoi(args[1]); err == nil {
						count = n
					}

					cs.History(count)

				}
			case "/quit":
				cs.Writeln("Goodbye!")
				goto quit
			default:
				cs.Writeln("Unknown command. Type /help for available commands.")
			}
		} else {
			if cs.CurrentChannel == "" {
				cs.Writeln("Please join a channel using /join <channel> first.")
			} else {
				msg := fmt.Sprintf("%s: %s", util.Colorize(cs.Username), line)
				db.SaveMessage(cs.CurrentChannel, cs.Username, line)
				broadcastMessage(cs.CurrentChannel, msg, nil)
			}
		}
	}
quit:
	if cs.CurrentChannel != "" {
		cs.LeaveChannel()
	}
	UnregisterSession(cs.Username)
}
