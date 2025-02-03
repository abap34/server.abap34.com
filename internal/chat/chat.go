package chat

import (
	"abap34-server/internal/db"
	"sync"
)


var (
	channels      = make(map[string]map[*ChatSession]bool)
	channelsMutex sync.Mutex

	sessions      = make(map[string]*ChatSession)
	sessionsMutex sync.Mutex
)

func broadcastMessage(channel, msg string, exclude *ChatSession) {
	db.SaveMessage(channel, "", msg)
	channelsMutex.Lock()
	sessMap, ok := channels[channel]
	channelsMutex.Unlock()
	if !ok {
		return
	}
	for cs := range sessMap {
		if cs == exclude {
			continue
		}
		cs.Write("\r\033[K")
		cs.Write("\r\033[K")
		cs.Writeln(msg)
		cs.Write(cs.Prompt)
	}
}

func RegisterSession(cs *ChatSession) {
	sessionsMutex.Lock()
	sessions[cs.Username] = cs
	sessionsMutex.Unlock()
}

func UnregisterSession(username string) {
	sessionsMutex.Lock()
	delete(sessions, username)
	sessionsMutex.Unlock()
}
