# server.abap34.com



## Description

Looking to chat?

No need to install any software—especially that bloated thing called a browser.
The perfect place is already right in front of you: the console.

## Usage

### Server

- `docker-compose.yaml` for production
- `docker-compose-dev.yaml` for development (hot-reload enabled)

### That's it!

All user can join the chat room with

```bash
$ ssh <server_ip> -p 12345
```

#### commands

Available commands:

| commands            | description                  |
| ------------------- | ---------------------------- |
| `/help`             | Show this help message       |
| `/join <channel>`   | Join a channel               |
| `/leave`            | Leave the current channel    |
| `/channels`         | List active channels         |
| `/users`            | List users                   |
| `/tp <user>`        | Teleport to a user           |
| `/msg <user> <msg>` | Send a private message       |
| `/history <count>`  | Show last `<count>` messages |
| `/quit`             | Quit the session             |
