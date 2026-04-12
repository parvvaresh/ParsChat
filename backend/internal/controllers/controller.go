package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/username/tcp-chat/internal/models"
	"github.com/username/tcp-chat/internal/services"
	"github.com/username/tcp-chat/internal/utils"
)

type Controller struct {
	Service *services.ChatService
}

func NewController(service *services.ChatService) *Controller {
	return &Controller{Service: service}
}

func (c *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		FullName string `json:"fullName"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.FullName) == "" || strings.TrimSpace(req.Password) == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, "username, fullName and password are required")
		return
	}

	hash := c.Service.HashPassword(req.Password)
	result, err := c.Service.DB.Exec("INSERT INTO users (username, full_name, password) VALUES (?, ?, ?)", req.Username, req.FullName, hash)
	if err != nil {
		utils.WriteAPIError(w, http.StatusConflict, "username already exists")
		return
	}

	id, _ := result.LastInsertId()
	utils.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id":        id,
		"username":  req.Username,
		"fullName":  req.FullName,
		"bio":       "",
		"avatarUrl": "",
	})
}

func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	var user models.User
	var storedHash string
	err := c.Service.DB.QueryRow("SELECT id, username, full_name, password, bio, avatar_url FROM users WHERE username = ?", req.Username).Scan(&user.ID, &user.Username, &user.FullName, &storedHash, &user.Bio, &user.AvatarURL)
	if err != nil || c.Service.HashPassword(req.Password) != storedHash {
		utils.WriteAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := c.Service.GenerateJWT(user.ID, user.Username)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":        user.ID,
		"username":  user.Username,
		"fullName":  user.FullName,
		"bio":       user.Bio,
		"avatarUrl": user.AvatarURL,
		"token":     token,
	})
}

func (c *Controller) GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := c.Service.DB.Query("SELECT id, username, full_name, bio, avatar_url FROM users ORDER BY username")
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var user models.User
		_ = rows.Scan(&user.ID, &user.Username, &user.FullName, &user.Bio, &user.AvatarURL)
		users = append(users, user)
	}

	utils.WriteJSON(w, http.StatusOK, users)
}

func (c *Controller) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		c.UpdateProfileHandler(w, r)
		return
	}

	c.GetProfileHandler(w, r)
}

func (c *Controller) GetProfileHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.URL.Query().Get("userId"))
	if userID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "userId is required")
		return
	}

	var user models.User
	err := c.Service.DB.QueryRow("SELECT id, username, full_name, bio, avatar_url FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username, &user.FullName, &user.Bio, &user.AvatarURL)
	if err != nil {
		utils.WriteAPIError(w, http.StatusNotFound, "user not found")
		return
	}

	utils.WriteJSON(w, http.StatusOK, user)
}

func (c *Controller) UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    int    `json:"userId"`
		Username  string `json:"username"`
		FullName  string `json:"fullName"`
		Bio       string `json:"bio"`
		AvatarURL string `json:"avatarUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.UserID == 0 || strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.FullName) == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, "userId, username and fullName are required")
		return
	}

	_, err := c.Service.DB.Exec(
		"UPDATE users SET username = ?, full_name = ?, bio = ?, avatar_url = ? WHERE id = ?",
		req.Username,
		req.FullName,
		req.Bio,
		req.AvatarURL,
		req.UserID,
	)
	if err != nil {
		utils.WriteAPIError(w, http.StatusConflict, "failed to update profile")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":        req.UserID,
		"username":  req.Username,
		"fullName":  req.FullName,
		"bio":       req.Bio,
		"avatarUrl": req.AvatarURL,
	})
}

func (c *Controller) GroupsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		c.CreateGroupHandler(w, r)
		return
	}

	c.GetGroupsHandler(w, r)
}

func (c *Controller) CreateGroupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		CreatorID int    `json:"creatorId"`
		MemberIDs []int  `json:"memberIds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if strings.TrimSpace(req.Name) == "" || req.CreatorID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "name and creatorId are required")
		return
	}

	tx, _ := c.Service.DB.Begin()
	result, err := tx.Exec("INSERT INTO groups (name, creator_id) VALUES (?, ?)", req.Name, req.CreatorID)
	if err != nil {
		_ = tx.Rollback()
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	groupID, _ := result.LastInsertId()
	_, _ = tx.Exec("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", groupID, req.CreatorID)
	for _, memberID := range req.MemberIDs {
		_, _ = tx.Exec("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", groupID, memberID)
	}
	_ = tx.Commit()

	utils.WriteJSON(w, http.StatusCreated, map[string]interface{}{"id": groupID, "name": req.Name})
}

func (c *Controller) GetGroupsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, "userId is required")
		return
	}

	rows, err := c.Service.DB.Query(`
		SELECT DISTINCT g.id, g.name, g.creator_id
		FROM groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY g.name`, userID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	groups := make([]models.Group, 0)
	for rows.Next() {
		var group models.Group
		_ = rows.Scan(&group.ID, &group.Name, &group.Creator)
		groups = append(groups, group)
	}

	utils.WriteJSON(w, http.StatusOK, groups)
}

func (c *Controller) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.URL.Query().Get("userId"))
	contactID, _ := strconv.Atoi(r.URL.Query().Get("contactId"))
	groupID, _ := strconv.Atoi(r.URL.Query().Get("groupId"))

	if userID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "userId is required")
		return
	}
	if groupID == 0 && contactID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "contactId or groupId is required")
		return
	}

	var (
		rows *sql.Rows
		err  error
	)

	if groupID > 0 {
		rows, err = c.Service.DB.Query(`
			SELECT id, from_user, to_user, group_id, content, media_url, media_type,
			       latitude, longitude, strftime('%s', timestamp) as ts
			FROM messages
			WHERE group_id = ?
			ORDER BY timestamp ASC
			LIMIT 100`, groupID)
	} else {
		rows, err = c.Service.DB.Query(`
			SELECT id, from_user, to_user, group_id, content, media_url, media_type,
			       latitude, longitude, strftime('%s', timestamp) as ts
			FROM messages
			WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
			ORDER BY timestamp ASC
			LIMIT 100`, userID, contactID, contactID, userID)
	}

	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	messages := make([]models.Message, 0)
	for rows.Next() {
		var message models.Message
		var id int
		var toUser, groupIDVal sql.NullInt64
		var content, mediaURL, mediaType sql.NullString
		var latitude, longitude sql.NullFloat64
		_ = rows.Scan(&id, &message.From, &toUser, &groupIDVal, &content, &mediaURL, &mediaType, &latitude, &longitude, &message.Timestamp)

		message.ID = id
		message.Type = "message"
		if toUser.Valid {
			message.To = int(toUser.Int64)
		}
		if groupIDVal.Valid {
			message.GroupID = int(groupIDVal.Int64)
		}
		if content.Valid {
			message.Content = content.String
		}
		if mediaURL.Valid {
			message.MediaURL = mediaURL.String
		}
		if mediaType.Valid {
			message.MediaType = mediaType.String
		}
		if latitude.Valid {
			lat := latitude.Float64
			message.Latitude = &lat
		}
		if longitude.Valid {
			lon := longitude.Float64
			message.Longitude = &lon
		}

		reactRows, _ := c.Service.DB.Query(`
			SELECT r.id, r.message_id, r.user_id, r.emoji, u.full_name
			FROM message_reactions r
			JOIN users u ON r.user_id = u.id
			WHERE r.message_id = ?
			ORDER BY r.created_at ASC`, id)

		reactions := make([]models.Reaction, 0)
		for reactRows.Next() {
			var reaction models.Reaction
			_ = reactRows.Scan(&reaction.ID, &reaction.MessageID, &reaction.UserID, &reaction.Emoji, &reaction.UserName)
			reactions = append(reactions, reaction)
		}
		reactRows.Close()
		if len(reactions) > 0 {
			message.Reactions = reactions
		}

		messages = append(messages, message)
	}

	utils.WriteJSON(w, http.StatusOK, messages)
}

func (c *Controller) SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	var message models.Message
	if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if message.From == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "from is required")
		return
	}
	if message.GroupID == 0 && message.To == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "to or groupId is required")
		return
	}
	if strings.TrimSpace(message.Content) == "" && strings.TrimSpace(message.MediaURL) == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, "content or mediaUrl is required")
		return
	}

	message.Timestamp = time.Now().Unix()

	var result sql.Result
	if message.GroupID > 0 {
		result, _ = c.Service.DB.Exec(
			"INSERT INTO messages (from_user, group_id, content, media_url, media_type, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)",
			message.From, message.GroupID, message.Content, message.MediaURL, message.MediaType, message.Latitude, message.Longitude,
		)

		rows, _ := c.Service.DB.Query("SELECT user_id FROM group_members WHERE group_id = ?", message.GroupID)
		for rows.Next() {
			var memberID int
			_ = rows.Scan(&memberID)
			if memberID == message.From {
				continue
			}
			data, _ := json.Marshal(message)
			c.Service.SendToUser(memberID, data)
		}
		rows.Close()
	} else {
		var blockCount int
		_ = c.Service.DB.QueryRow("SELECT COUNT(*) FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?", message.To, message.From).Scan(&blockCount)
		if blockCount > 0 {
			utils.WriteAPIError(w, http.StatusForbidden, "user has blocked you")
			return
		}

		result, _ = c.Service.DB.Exec(
			"INSERT INTO messages (from_user, to_user, content, media_url, media_type, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)",
			message.From, message.To, message.Content, message.MediaURL, message.MediaType, message.Latitude, message.Longitude,
		)

		data, _ := json.Marshal(message)
		c.Service.SendToUser(message.To, data)
	}

	messageID, _ := result.LastInsertId()
	utils.WriteJSON(w, http.StatusCreated, map[string]interface{}{"status": "ok", "messageId": messageID})
}

func (c *Controller) TypingHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From int `json:"from"`
		To   int `json:"to"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	data, _ := json.Marshal(map[string]interface{}{"type": "typing", "from": req.From})
	c.Service.SendToUser(req.To, data)
	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *Controller) UploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "file field required")
		return
	}
	defer file.Close()

	_ = os.MkdirAll("uploads", 0755)
	ext := filepath.Ext(header.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	dst, err := os.Create(filepath.Join("uploads", filename))
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to save file")
		return
	}
	defer dst.Close()

	_, _ = io.Copy(dst, file)
	utils.WriteJSON(w, http.StatusCreated, map[string]string{"url": fmt.Sprintf("/uploads/%s", filename)})
}

func (c *Controller) SSEHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.URL.Query().Get("userId"))
	if userID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "userId is required")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	client := c.Service.RegisterClient(userID)
	defer c.Service.UnregisterClient(userID)

	_, _ = fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	for {
		select {
		case msg := <-client.Messages:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-client.Done:
			return
		}
	}
}

func (c *Controller) OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	utils.WriteJSON(w, http.StatusOK, c.Service.OnlineUserIDs())
}

func (c *Controller) BlockUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BlockerID int `json:"blockerId"`
		BlockedID int `json:"blockedId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec("INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)", req.BlockerID, req.BlockedID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to block user")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
}

func (c *Controller) UnblockUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BlockerID int `json:"blockerId"`
		BlockedID int `json:"blockedId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec("DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?", req.BlockerID, req.BlockedID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to unblock user")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "unblocked"})
}

func (c *Controller) GetBlockedUsersHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	rows, err := c.Service.DB.Query("SELECT blocked_id FROM blocked_users WHERE blocker_id = ?", userID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	blockedIDs := make([]int, 0)
	for rows.Next() {
		var id int
		_ = rows.Scan(&id)
		blockedIDs = append(blockedIDs, id)
	}

	utils.WriteJSON(w, http.StatusOK, blockedIDs)
}

func (c *Controller) MarkMessageReadHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MessageID int `json:"messageId"`
		UserID    int `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec("INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)", req.MessageID, req.UserID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to mark as read")
		return
	}

	var fromUser sql.NullInt64
	_ = c.Service.DB.QueryRow("SELECT from_user FROM messages WHERE id = ?", req.MessageID).Scan(&fromUser)
	if fromUser.Valid && int(fromUser.Int64) != req.UserID {
		data, _ := json.Marshal(map[string]interface{}{"type": "read_receipt", "messageId": req.MessageID, "userId": req.UserID})
		c.Service.SendToUser(int(fromUser.Int64), data)
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *Controller) AddReactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MessageID int    `json:"messageId"`
		UserID    int    `json:"userId"`
		Emoji     string `json:"emoji"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := c.Service.DB.Exec("INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)", req.MessageID, req.UserID, req.Emoji)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to add reaction")
		return
	}

	c.broadcastReaction(req.MessageID, req.UserID, "add", req.Emoji)
	id, _ := result.LastInsertId()
	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{"id": id, "status": "ok"})
}

func (c *Controller) RemoveReactionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MessageID int    `json:"messageId"`
		UserID    int    `json:"userId"`
		Emoji     string `json:"emoji"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec("DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?", req.MessageID, req.UserID, req.Emoji)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to remove reaction")
		return
	}

	c.broadcastReaction(req.MessageID, req.UserID, "remove", req.Emoji)
	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *Controller) GetMessageReactionsHandler(w http.ResponseWriter, r *http.Request) {
	messageID := r.URL.Query().Get("messageId")
	rows, err := c.Service.DB.Query(`
		SELECT r.id, r.message_id, r.user_id, r.emoji, u.full_name
		FROM message_reactions r
		JOIN users u ON r.user_id = u.id
		WHERE r.message_id = ?
		ORDER BY r.created_at ASC`, messageID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	reactions := make([]models.Reaction, 0)
	for rows.Next() {
		var reaction models.Reaction
		_ = rows.Scan(&reaction.ID, &reaction.MessageID, &reaction.UserID, &reaction.Emoji, &reaction.UserName)
		reactions = append(reactions, reaction)
	}

	utils.WriteJSON(w, http.StatusOK, reactions)
}

func (c *Controller) LeaveGroupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID int `json:"groupId"`
		UserID  int `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", req.GroupID, req.UserID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to leave group")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "left"})
}

func (c *Controller) RemoveGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID   int `json:"groupId"`
		UserID    int `json:"userId"`
		RemoverID int `json:"removerId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	var creatorID int
	err := c.Service.DB.QueryRow("SELECT creator_id FROM groups WHERE id = ?", req.GroupID).Scan(&creatorID)
	if err != nil || creatorID != req.RemoverID {
		utils.WriteAPIError(w, http.StatusForbidden, "only group creator can remove members")
		return
	}

	_, err = c.Service.DB.Exec("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", req.GroupID, req.UserID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (c *Controller) AddGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID int `json:"groupId"`
		UserID  int `json:"userId"`
		AdderID int `json:"adderId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.GroupID == 0 || req.UserID == 0 || req.AdderID == 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, "groupId, userId and adderId are required")
		return
	}

	var creatorID int
	err := c.Service.DB.QueryRow("SELECT creator_id FROM groups WHERE id = ?", req.GroupID).Scan(&creatorID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusNotFound, "group not found")
		return
	}

	if creatorID != req.AdderID {
		utils.WriteAPIError(w, http.StatusForbidden, "only group creator can add members")
		return
	}

	_, err = c.Service.DB.Exec("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)", req.GroupID, req.UserID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (c *Controller) GetGroupMembersHandler(w http.ResponseWriter, r *http.Request) {
	groupID := r.URL.Query().Get("groupId")
	rows, err := c.Service.DB.Query(`
		SELECT u.id, u.username, u.full_name
		FROM users u
		JOIN group_members gm ON u.id = gm.user_id
		WHERE gm.group_id = ?
		ORDER BY u.full_name`, groupID)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer rows.Close()

	members := make([]models.User, 0)
	for rows.Next() {
		var user models.User
		_ = rows.Scan(&user.ID, &user.Username, &user.FullName)
		members = append(members, user)
	}

	utils.WriteJSON(w, http.StatusOK, members)
}

func (c *Controller) SavePublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    int    `json:"userId"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, "invalid request")
		return
	}

	_, err := c.Service.DB.Exec(`INSERT INTO user_keys (user_id, public_key, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET public_key = ?, updated_at = CURRENT_TIMESTAMP`,
		req.UserID, req.PublicKey, req.PublicKey)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, "failed to save key")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *Controller) GetPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	var publicKey string
	err := c.Service.DB.QueryRow("SELECT public_key FROM user_keys WHERE user_id = ?", userID).Scan(&publicKey)
	if err != nil {
		utils.WriteAPIError(w, http.StatusNotFound, "key not found")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{"publicKey": publicKey})
}

func (c *Controller) broadcastReaction(messageID int, userID int, action string, emoji string) {
	var fromUser, toUser, groupID sql.NullInt64
	_ = c.Service.DB.QueryRow("SELECT from_user, to_user, group_id FROM messages WHERE id = ?", messageID).Scan(&fromUser, &toUser, &groupID)

	data, _ := json.Marshal(map[string]interface{}{
		"type":      "reaction",
		"action":    action,
		"messageId": messageID,
		"userId":    userID,
		"emoji":     emoji,
	})

	if groupID.Valid {
		rows, _ := c.Service.DB.Query("SELECT user_id FROM group_members WHERE group_id = ?", groupID.Int64)
		for rows.Next() {
			var memberID int
			_ = rows.Scan(&memberID)
			if memberID != userID {
				c.Service.SendToUser(memberID, data)
			}
		}
		rows.Close()
		return
	}

	if fromUser.Valid && int(fromUser.Int64) != userID {
		c.Service.SendToUser(int(fromUser.Int64), data)
	}
	if toUser.Valid && int(toUser.Int64) != userID {
		c.Service.SendToUser(int(toUser.Int64), data)
	}
}
