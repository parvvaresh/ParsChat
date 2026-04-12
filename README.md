# ParsChat

ParsChat is a full-stack real-time chat application with a Go backend and a React frontend.

## Overview

- Backend: Go (`net/http`) + SQLite + JWT auth + SSE realtime stream
- Frontend: React + TypeScript + Zustand + Axios + Vite
- Realtime: Server-Sent Events for incoming messages, typing signals, and online/offline updates
- Storage: SQLite database (`chat.db`) and local upload storage (`uploads/`)

## Key Features

- User authentication (register/login with JWT)
- One-to-one chat
- Group chat (create group, add/remove members, leave group)
- Typing indicators
- Online/offline presence
- Block / unblock users
- Media and file sharing (image, video, audio, generic files)
- Voice message recording from browser microphone
- Location sharing (latitude/longitude with map link)
- Emoji picker in composer
- Profile modal (view/edit username, full name, bio, avatar)
- Message reactions API support

## Project Structure

```text
ParsChat/
├── backend/
│   ├── cmd/server/main.go
│   ├── internal/
│   │   ├── config/
│   │   ├── controllers/
│   │   ├── middleware/
│   │   ├── models/
│   │   ├── routes/
│   │   ├── server/
│   │   ├── services/
│   │   └── utils/
│   ├── public/
│   ├── uploads/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── go.mod
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── features/
│   │   ├── hooks/
│   │   ├── lib/
│   │   ├── services/
│   │   └── types.ts
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── package.json
│   └── vite.config.ts
├── API_AUDIT.md
├── LOCATION_SHARING.md
└── docker-compose.yml
```

## Tech Stack

### Backend
- Go 1.21
- SQLite (`github.com/mattn/go-sqlite3`)
- JWT (`github.com/golang-jwt/jwt/v5`)
- SSE over HTTP (`/events`)

### Frontend
- React 18
- TypeScript
- Zustand (state management)
- Axios (HTTP client)
- Vite (dev server and bundler)

## Requirements

- Go 1.21+
- Node.js 20+
- npm 9+
- Docker + Docker Compose (optional)

## Environment Variables

Backend reads these variables:

- `PORT` (default: `8080`)
- `DB_PATH` (default: `./chat.db`)
- `JWT_SECRET` (default is development-only fallback)

Frontend (Vite) can use:

- `VITE_PROXY_TARGET` (default: `http://localhost:8080`)

## Run Locally (Recommended for Development)

### 1) Start backend

```bash
cd backend
go mod tidy
go run ./cmd/server
```

Backend URL: `http://localhost:8080`

### 2) Start frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend URL: `http://localhost:5173`

Vite proxies `/api`, `/events`, and `/uploads` to the backend.

## Build Frontend for Backend Static Serving

If you build the frontend, backend can serve `frontend/dist` automatically.

```bash
cd frontend
npm install
npm run build
```

Then run backend as usual:

```bash
cd backend
go run ./cmd/server
```

## Docker

### Run full stack from root

```bash
docker compose up --build
```

Services:

- Backend: `http://localhost:8080`
- Frontend: `http://localhost:5173`

### Run only backend

```bash
cd backend
docker compose up --build
```

### Run only frontend

```bash
cd frontend
docker compose up --build
```

### Stop containers

From whichever directory you started compose:

```bash
docker compose down
```

## API Summary

### Auth
- `POST /api/register`
- `POST /api/login`

### Users and Profile
- `GET /api/users`
- `GET /api/profile?userId=...`
- `POST /api/profile`

### Messaging and Realtime
- `GET /api/messages`
- `POST /api/send`
- `POST /api/typing`
- `GET /events`

### Uploads and Presence
- `POST /api/upload`
- `GET /api/online`

### Blocking
- `POST /api/block`
- `POST /api/unblock`
- `GET /api/blocked`

### Groups
- `GET /api/groups`
- `POST /api/groups`
- `POST /api/group/add`
- `POST /api/group/remove`
- `POST /api/group/leave`
- `GET /api/group/members`

### Reads and Reactions
- `POST /api/messages/read`
- `POST /api/reactions/add`
- `POST /api/reactions/remove`
- `GET /api/reactions`

### Key Exchange
- `POST /api/keys/save`
- `GET /api/keys/get`

For detailed request/response shapes, check `API_AUDIT.md`.

## Database Notes

Database schema is initialized automatically on startup.

Current tables include:

- `users`
- `groups`
- `group_members`
- `messages`
- `message_reads`
- `message_reactions`
- `blocked_users`
- `user_keys`

The service also performs lightweight migration attempts for profile fields (`bio`, `avatar_url`) on startup.

## Troubleshooting

### `vite: not found`

Install frontend dependencies first:

```bash
cd frontend
npm install
npm run dev
```

### `Cannot find module 'zustand'` or other frontend package errors

```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### Port already in use

- Change backend `PORT`
- Or stop the process currently using `8080` / `5173`

### Uploads not accessible

- Ensure backend is running
- Ensure `uploads/` exists and is writable
- Access files via `/uploads/<filename>`

## Security Notes

- Default `JWT_SECRET` fallback is for development only.
- Set a strong `JWT_SECRET` in production.
- Consider running behind HTTPS and adding stricter auth checks for profile update ownership.

## Related Docs

- `API_AUDIT.md`: API contracts and endpoint details
- `LOCATION_SHARING.md`: location-sharing behavior

## License

No license file is currently included in this repository.
