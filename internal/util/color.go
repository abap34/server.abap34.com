package util

import (
	"math/rand"
	"sync"
)

var (
	// MEMO: We have to choose the color which is visible on the black background
	userColors      = make(map[string]string)
	userColorsMutex sync.Mutex
)

const (
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Magenta   = "\033[35m"
	Cyan      = "\033[36m"
	Grey      = "\033[37m"
	LightGrey = "\033[90m"
	Reset     = "\033[0m"
	LightBlue = "\033[94m"
)

func Colorize(username string, color string) string {
	userColorsMutex.Lock()
	defer userColorsMutex.Unlock()

	if color != "" {
		return color + username + "\033[0m"
	}

	if existingColor, ok := userColors[username]; ok {
		return existingColor + username + "\033[0m"
	}

	if color == "" {
		// random color from color list
		colors := []string{Red, Green, Yellow, Blue, Magenta, Cyan}
		color = colors[rand.Intn(len(colors))]
	}

	userColors[username] = color
	return color + username + "\033[0m"
}

func Boldstring(s string) string {
	return "\033[1m" + s + "\033[0m"
}
