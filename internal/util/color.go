package util

import (
	"math/rand"
	"sync"
)

var (
	// MEMO: We have to choose the color which is visible on the black background
	availableColors = []string{
		"\033[31m", // red
		"\033[32m", // green
		"\033[33m", // yellow
		// "\033[34m", // blue
		"\033[35m", // magenta
		"\033[36m", // cyan
	}
	userColors      = make(map[string]string)
	userColorsMutex sync.Mutex
)

func Colorize(username string) string {
	userColorsMutex.Lock()
	defer userColorsMutex.Unlock()
	color, ok := userColors[username]
	if !ok {
		color = availableColors[rand.Intn(len(availableColors))]
		userColors[username] = color
	}
	return color + username + "\033[0m"
}

func Boldstring(s string) string {
	return "\033[1m" + s + "\033[0m"
}
