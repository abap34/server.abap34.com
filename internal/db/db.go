package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func Init() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS messages (
		id INT AUTO_INCREMENT PRIMARY KEY,
		channel VARCHAR(255) NOT NULL,
		username VARCHAR(255) NOT NULL,
		message TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = DB.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Error creating messages table: %v", err)
	}
	log.Println("Database initialized successfully.")
}

func SaveMessage(channel, username, message string) {
	_, err := DB.Exec("INSERT INTO messages (channel, username, message) VALUES (?, ?, ?)",
		channel, username, message)
	if err != nil {
		log.Printf("Error saving message: %v", err)
	}
}

func LoadMessages(channel string, limit int) ([]string, error) {
	rows, err := DB.Query("SELECT username, message FROM messages WHERE channel = ? ORDER BY created_at DESC LIMIT ?", channel, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []string
	for rows.Next() {
		var username, message string
		if err := rows.Scan(&username, &message); err != nil {
			return nil, err
		}
		messages = append(messages, fmt.Sprintf("%s: %s", username, message))
	}

	// Reverse the order of messages
	var reversed []string
	for i := len(messages) - 1; i >= 0; i-- {
		reversed = append(reversed, messages[i])
	}
	return reversed, nil
}
