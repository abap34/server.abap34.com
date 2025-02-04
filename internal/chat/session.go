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
	"sync"
	"time"

	"github.com/cli/oauth/device"
	"github.com/gliderlabs/ssh"
	"golang.org/x/term"

	"abap34-server/internal/db"
	"abap34-server/internal/util"
)

const MESSAGE_LOAD_COUNT = 15
const BUFFER_SIZE = 1000

// ChatSession wraps user session data
type ChatSession struct {
	Session        ssh.Session
	Term           *term.Terminal
	Prompt         string
	Username       string
	CurrentChannel string

	// Mutex for the slice of local messages we display in real time
	localMutex  sync.Mutex
	localBuffer []string
}

// Write low-level write (for authentication steps, etc.)
func (cs *ChatSession) Write(msg string) {
	cs.Term.Write([]byte(msg))
}

// Writeln convenience - includes newline
func (cs *ChatSession) Writeln(msg string) {
	cs.Write(msg + "\n")
}

// addLocalMessage appends a line of text to this session’s local buffer
func (cs *ChatSession) addLocalMessage(msg string) {
	cs.localMutex.Lock()
	defer cs.localMutex.Unlock()
	cs.localBuffer = append(cs.localBuffer, msg)
	if len(cs.localBuffer) > BUFFER_SIZE {
		cs.localBuffer = cs.localBuffer[len(cs.localBuffer)-BUFFER_SIZE:]
	}
}

// redrawScreen clears the screen and redraws the local buffer
func (cs *ChatSession) redrawScreen() {
	cs.localMutex.Lock()
	defer cs.localMutex.Unlock()

	// ANSI: Clear screen and move cursor to top-left
	cs.Write("\033[2J\033[H")

	// Print stored lines
	for _, line := range cs.localBuffer {
		cs.Write(line + "\n")
	}

	// Repaint the prompt
	cs.Write(cs.Prompt)
}

// HandleSession main entry point
func HandleSession(s ssh.Session) {
	// Possibly authenticate via GitHub public key
	authPassed := false
	if pk := s.PublicKey(); pk != nil {
		if err := authenticateViaPublicKey(s, pk); err == nil {
			authPassed = true
		} else {
			s.Write([]byte("[Public key auth error] " + err.Error() + "\n"))
		}
	}

	_, _, isPty := s.Pty()
	if !isPty {
		s.Write([]byte("PTY required.\n"))
		s.Exit(1)
		return
	}

	termObj := term.NewTerminal(s, "> ")
	cs := &ChatSession{
		Session:  s,
		Term:     termObj,
		Prompt:   "> ",
		Username: s.User(),
	}

	// If GitHub public key failed, do device flow
	if !authPassed {
		if err := authenticateGitHub(cs); err != nil {
			cs.Writeln("GitHub authentication failed. Exiting.")
			s.Exit(1)
			return
		}
	}

	RegisterSession(cs)

	// Welcome
	cs.addLocalMessage(util.Boldstring(util.Colorize("==== Welcome to abap34's chat server! ====", "")))
	cs.addLocalMessage("└ Your username is: " + util.Colorize(cs.Username, ""))
	cs.addLocalMessage("")
	cs.PrintHelp()
	cs.addLocalMessage("")

	// Join default channel
	cs.JoinChannel("general")

	// Draw initial screen
	cs.redrawScreen()

	// Read user input line by line
	for {
		line, err := cs.Term.ReadLine()
		if err != nil {
			// If user disconnects, or an error reading input
			break
		}
		handleUserInput(cs, strings.TrimSpace(line))
		cs.redrawScreen()
	}

	// Cleanup
	if cs.CurrentChannel != "" {
		cs.LeaveChannel()
	}
	UnregisterSession(cs.Username)
}

// authenticateViaPublicKey checks if user’s GitHub-registered SSH key matches
func authenticateViaPublicKey(s ssh.Session, pk ssh.PublicKey) error {
	username := s.User()
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to retrieve GitHub public keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub user keys not found (status %d)", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading keys: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err == nil && ssh.KeysEqual(pk, authorizedKey) {
			return nil
		}
	}
	return fmt.Errorf("no matching public key found for GitHub user %s", username)
}

// authenticateGitHub device flow OAuth
func authenticateGitHub(cs *ChatSession) error {
	cs.Writeln("GitHub authentication is required. Press Enter to begin.")
	_, err := cs.Term.ReadLine()
	if err != nil {
		return err
	}

	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		return fmt.Errorf("GITHUB_CLIENT_ID not set")
	}

	httpClient := http.DefaultClient
	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, []string{"read:user"})
	if err != nil {
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
		return err
	}

	gUser, err := fetchGitHubUser(accessToken.Token)
	if err != nil {
		return err
	}

	cs.Username = gUser
	cs.Writeln("Authentication successful! You are logged in as " + util.Colorize(cs.Username, ""))
	cs.Writeln(util.Boldstring(
		"Hint: Use your GitHub-registered public key next time. " +
			"See: https://github.com/abap34/server.abap34.com/blob/main/README.md#login"))
	return nil
}

// fetchGitHubUser retrieves the GitHub user login from an OAuth token
func fetchGitHubUser(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "token "+token)
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

// handleUserInput parses slash-commands or normal chat messages
func handleUserInput(cs *ChatSession, line string) {
	if line == "" {
		return
	}
	if strings.HasPrefix(line, "/") {
		args := strings.SplitN(line, " ", 3)
		switch args[0] {
		case "/help":
			cs.PrintHelp()
		case "/join":
			if len(args) < 2 {
				cs.addLocalMessage("Usage: /join <channel>")
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
				cs.addLocalMessage("Usage: /tp <user>")
			} else {
				cs.Teleport(args[1])
			}
		case "/msg":
			if len(args) < 3 {
				cs.addLocalMessage("Usage: /msg <user> <message>")
			} else {
				cs.PrivateMessage(args[1], args[2])
			}
		case "/history":
			if len(args) < 2 {
				cs.addLocalMessage("Usage: /history <count>")
			} else {
				n, err := strconv.Atoi(args[1])
				if err != nil {
					cs.addLocalMessage("Count must be numeric.")
					return
				}
				cs.History(n)
			}
		case "/quit":
			cs.addLocalMessage("Goodbye!")
			cs.redrawScreen()
			cs.Session.Close()
		default:
			cs.addLocalMessage("Unknown command. Type /help for usage.")
		}
	} else {
		if cs.CurrentChannel == "" {
			cs.addLocalMessage("Please join a channel with /join <channel> first.")
		} else {
			msg := fmt.Sprintf("%s: %s", util.Colorize(cs.Username, ""), line)
			broadcastMessage(cs.CurrentChannel, msg, cs.Username, nil)
		}
	}
}

// PrintHelp lists available commands
func (cs *ChatSession) PrintHelp() {
	cs.addLocalMessage("Available commands:")
	cs.addLocalMessage("  /help                - Show this help message")
	cs.addLocalMessage("  /join <channel>      - Join a channel")
	cs.addLocalMessage("  /leave               - Leave the current channel")
	cs.addLocalMessage("  /channels            - List active channels")
	cs.addLocalMessage("  /users               - List users")
	cs.addLocalMessage("  /tp <user>           - Teleport to a user")
	cs.addLocalMessage("  /msg <user> <msg>    - Send a private message")
	cs.addLocalMessage("  /history <count>     - Show last <count> messages")
	cs.addLocalMessage("  /quit                - Quit the session")
}

// JoinChannel puts user into a specific channel
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
	cs.addLocalMessage("Joined channel [" + channel + "]")

	msgs, err := db.LoadMessages(channel, MESSAGE_LOAD_COUNT)
	if err != nil {
		cs.addLocalMessage("Error loading history: " + err.Error())
	} else if len(msgs) > 0 {
		cs.addLocalMessage("Last messages in [" + channel + "]:")
		for _, m := range msgs {
			cs.addLocalMessage("  " + m)
		}
	}
	broadcastMessage(channel, util.Colorize("*** "+cs.Username+" has joined ***", util.LightGrey), "system", cs)
	log.Printf("User '%s' joined channel '%s'", cs.Username, channel)
}

// LeaveChannel exits the current channel
func (cs *ChatSession) LeaveChannel() {
	if cs.CurrentChannel == "" {
		cs.addLocalMessage("You are not in any channel.")
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
	broadcastMessage(cs.CurrentChannel, util.Colorize("*** "+cs.Username+" has left ***", util.LightGrey), "system", cs)
	cs.addLocalMessage("Left channel [" + cs.CurrentChannel + "]")
	cs.CurrentChannel = ""
}

// ListChannels displays all active channels and members
func (cs *ChatSession) ListChannels() {
	cs.addLocalMessage("All channels:")
	channelsMutex.Lock()
	for channel, sessMap := range channels {
		users := make([]string, 0, len(sessMap))
		for sess := range sessMap {
			users = append(users, sess.Username)
		}
		cs.addLocalMessage("  " + channel + " (" + strings.Join(users, ", ") + ")")
	}
	channelsMutex.Unlock()
}

// ListUsers shows all active users
func (cs *ChatSession) ListUsers() {
	cs.addLocalMessage("Active users:")
	sessionsMutex.Lock()
	for name, sess := range sessions {
		cs.addLocalMessage("  " + name + " is at " + sess.CurrentChannel)
	}
	sessionsMutex.Unlock()
}

// Teleport moves target user to current user’s channel
func (cs *ChatSession) Teleport(target string) {
	sessionsMutex.Lock()
	recipient, ok := sessions[target]
	sessionsMutex.Unlock()
	if !ok {
		cs.addLocalMessage("User " + target + " not found.")
		return
	}
	recipient.JoinChannel(cs.CurrentChannel)
	cs.addLocalMessage("Teleported " + target + " to " + cs.CurrentChannel)
}

// PrivateMessage sends a direct message to user
func (cs *ChatSession) PrivateMessage(target, message string) {
	sessionsMutex.Lock()
	recipient, ok := sessions[target]
	sessionsMutex.Unlock()
	if !ok {
		cs.addLocalMessage("User " + target + " not found.")
		return
	}
	msg := fmt.Sprintf("[Private] %s: %s", cs.Username, message)
	db.SaveMessage("", cs.Username, msg)
	recipient.addLocalMessage(msg)
	cs.addLocalMessage("[Private] to " + target + ": " + message)
}

// History loads last N messages from current channel
func (cs *ChatSession) History(count int) {
	if cs.CurrentChannel == "" {
		cs.addLocalMessage("Please join a channel: /join <channel>")
		return
	}
	msgs, err := db.LoadMessages(cs.CurrentChannel, count)

	if err != nil {
		cs.addLocalMessage("Error loading history: " + err.Error())
	} else if len(msgs) > 0 {
		cs.addLocalMessage("Last messages in [" + cs.CurrentChannel + "]:")
		for _, m := range msgs {
			cs.addLocalMessage("  " + m)
		}
	}
}
