# TCP Chat Application

> **WARNING - CRITICAL INFRASTRUCTURE**  
> This repository is designed to facilitate communication for Iranian citizens during protests and internet shutdowns. It operates on domestic servers to maintain connectivity when external internet access is restricted or censored. Use responsibly and ensure secure deployment in sensitive environments.

A feature-rich chat application with a WhatsApp-like UI, built with Go and Server-Sent Events for real-time communication.

---

## Features

### Authentication and Security
* **User Registration and Login** - Complete authentication system
* **Password Hashing** - Using SHA256
* **Secure Sessions** - User management with SSE

### Messaging
* **Private Chat** - One-on-one messaging
* **Group Chats** - Create and manage groups
* **File Sharing** - Send images, videos, and files
* **Typing Indicator** - Shows when user is typing
* **Real-time Messaging** - Using Server-Sent Events

### User Interface
* **WhatsApp-like Design** - Modern and familiar UI
* **Dark Mode** - Eye-comfortable dark theme
* **Responsive** - Works on desktop and mobile
* **Media Preview** - Display images and videos in chat
* **Smooth Animations** - Professional user experience

### Technical
* **SQLite Database** - Data storage
* **Server-Sent Events** - Real-time communications
* **RESTful API** - Modern architecture
* **Docker** - Ready for deployment
* **Offline Capability** - Works on local networks without internet

---

## Project Structure

```
chatApp/
├── cmd/
│   └── server/
│       └── main.go        # Main server with SSE and API
├── public/
│   ├── index.html         # Web UI
│   └── app.js             # Frontend logic
├── uploads/               # Uploaded files
├── chat.db                # SQLite database
├── Dockerfile             # Docker image
├── docker-compose.yml     # Service configuration
├── go.mod                 # Go dependencies
└── README.md              # This file
```

---

## Quick Start

### Prerequisites

* Go 1.21 or later
* Docker and Docker Compose (optional)
* Modern web browser

---

## Running Locally

### 1. Install Dependencies

```bash
go mod download
```

### 2. Run Server

```bash
go run cmd/server/main.go
```

Server runs on `http://localhost:8080`

### 3. Open in Browser

Go to `http://localhost:8080` and:
1. Register or login
2. Search for other users
3. Start chatting!

---

## Running with Docker

### Build and Run

```bash
docker-compose up --build
```

### Access the Application

Go to `http://localhost:8080`

### Stop Services

```bash
docker-compose down
```

---

## Usage Guide

### Registration and Login

1. Open the login page
2. Click "Register"
3. Enter username, full name, and password
4. After registration, login

### Starting a Private Chat

1. Click the chat button (New Chat)
2. Select a user from the list
3. Start sending messages!

### Creating a Group

1. Click the group button (New Group)
2. Enter group name
3. Select members from the list
4. Click "Create Group"

### Sending Media

1. Click the attachment button in the input area
2. Select an image or video
3. File is automatically uploaded and sent

### Additional Features

* **Search**: Use the search box to find contacts
* **Typing**: When you type, the other party sees it
* **Online Status**: See online status indicator

---

## API Endpoints

### Authentication

* `POST /api/register` - Register new user
* `POST /api/login` - User login

### Users and Groups

* `GET /api/users` - Get user list
* `GET /api/groups?userId={id}` - Get user's groups
* `POST /api/groups` - Create new group

### Messages

* `GET /api/messages?userId={id}&contactId={id}` - Get private messages
* `GET /api/messages?userId={id}&groupId={id}` - Get group messages
* `GET /events?userId={id}` - SSE connection

### Media

* `POST /api/upload` - Upload file
* `GET /uploads/{filename}` - Get uploaded file

---

## Database Schema

### users table
```sql
- id (INTEGER PRIMARY KEY)
- username (TEXT UNIQUE)
- full_name (TEXT)
- password (TEXT - SHA256 hash)
- created_at (DATETIME)
```

### groups table
```sql
- id (INTEGER PRIMARY KEY)
- name (TEXT)
- creator_id (INTEGER)
- created_at (DATETIME)
```

### group_members table
```sql
- group_id (INTEGER)
- user_id (INTEGER)
- joined_at (DATETIME)
```

### messages table
```sql
- id (INTEGER PRIMARY KEY)
- from_user (INTEGER)
- to_user (INTEGER, nullable)
- group_id (INTEGER, nullable)
- content (TEXT, nullable)
- media_url (TEXT, nullable)
- media_type (TEXT, nullable)
- timestamp (DATETIME)
```

---

## Production Deployment

### Environment Variables

```bash
PORT=8080              # Server port
```

### Security Notes

1. Use HTTPS in production
2. Enforce strong passwords
3. Implement rate limiting
4. Regular database backups
5. Input validation and sanitization

---

## Development

### Build from Source

```bash
CGO_ENABLED=1 go build -o chat-server ./cmd/server
./chat-server
```

### Dependencies

* `github.com/mattn/go-sqlite3` - SQLite driver

---

## TODO / Future Improvements

- [ ] JWT authentication
- [ ] End-to-end encryption
- [ ] Voice/video calls
- [ ] Push notifications
- [ ] Emoji reactions
- [ ] Location sharing
- [ ] Voice messages
- [ ] Custom themes
- [ ] Mobile app (React Native)

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## License

This project is released under the MIT License.

---

## Ethical Use

This tool is designed to help free communication during critical times. Please:

* Use responsibly and legally
* Respect user privacy
* Avoid misuse
* Be aware of security requirements

---

## Support

For issues, questions, or feature requests:
* Create an Issue on GitHub
* Join discussions

---

**Built for free communication**


