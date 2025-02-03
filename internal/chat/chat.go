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

// broadcastMessage sends a message to everyone in the channel except “exclude”
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
        cs.addLocalMessage(msg)
    }
}

// RegisterSession adds a new session to the global map
func RegisterSession(cs *ChatSession) {
    sessionsMutex.Lock()
    sessions[cs.Username] = cs
    sessionsMutex.Unlock()
}

// UnregisterSession removes a session from the global map
func UnregisterSession(username string) {
    sessionsMutex.Lock()
    delete(sessions, username)
    sessionsMutex.Unlock()
}