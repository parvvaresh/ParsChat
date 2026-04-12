package routes

import (
	"net/http"

	"github.com/username/tcp-chat/internal/controllers"
	"github.com/username/tcp-chat/internal/middleware"
)

func Register(mux *http.ServeMux, controller *controllers.Controller) {
	allowGet := map[string]bool{http.MethodGet: true}
	allowPost := map[string]bool{http.MethodPost: true}
	allowGetPost := map[string]bool{http.MethodGet: true, http.MethodPost: true}

	mux.HandleFunc("/api/register", middleware.MethodGuard(allowPost, controller.RegisterHandler))
	mux.HandleFunc("/api/login", middleware.MethodGuard(allowPost, controller.LoginHandler))
	mux.HandleFunc("/api/users", middleware.MethodGuard(allowGet, controller.GetUsersHandler))
	mux.HandleFunc("/api/profile", middleware.MethodGuard(allowGetPost, controller.ProfileHandler))
	mux.HandleFunc("/api/groups", middleware.MethodGuard(allowGetPost, controller.GroupsHandler))
	mux.HandleFunc("/api/messages", middleware.MethodGuard(allowGet, controller.GetMessagesHandler))
	mux.HandleFunc("/api/send", middleware.MethodGuard(allowPost, controller.SendMessageHandler))
	mux.HandleFunc("/api/typing", middleware.MethodGuard(allowPost, controller.TypingHandler))
	mux.HandleFunc("/api/upload", middleware.MethodGuard(allowPost, controller.UploadHandler))
	mux.HandleFunc("/api/online", middleware.MethodGuard(allowGet, controller.OnlineUsersHandler))
	mux.HandleFunc("/api/block", middleware.MethodGuard(allowPost, controller.BlockUserHandler))
	mux.HandleFunc("/api/unblock", middleware.MethodGuard(allowPost, controller.UnblockUserHandler))
	mux.HandleFunc("/api/blocked", middleware.MethodGuard(allowGet, controller.GetBlockedUsersHandler))
	mux.HandleFunc("/api/group/leave", middleware.MethodGuard(allowPost, controller.LeaveGroupHandler))
	mux.HandleFunc("/api/group/add", middleware.MethodGuard(allowPost, controller.AddGroupMemberHandler))
	mux.HandleFunc("/api/group/remove", middleware.MethodGuard(allowPost, controller.RemoveGroupMemberHandler))
	mux.HandleFunc("/api/group/members", middleware.MethodGuard(allowGet, controller.GetGroupMembersHandler))
	mux.HandleFunc("/api/messages/read", middleware.MethodGuard(allowPost, controller.MarkMessageReadHandler))
	mux.HandleFunc("/api/reactions/add", middleware.MethodGuard(allowPost, controller.AddReactionHandler))
	mux.HandleFunc("/api/reactions/remove", middleware.MethodGuard(allowPost, controller.RemoveReactionHandler))
	mux.HandleFunc("/api/reactions", middleware.MethodGuard(allowGet, controller.GetMessageReactionsHandler))
	mux.HandleFunc("/api/keys/save", middleware.MethodGuard(allowPost, controller.SavePublicKeyHandler))
	mux.HandleFunc("/api/keys/get", middleware.MethodGuard(allowGet, controller.GetPublicKeyHandler))
	mux.HandleFunc("/events", middleware.MethodGuard(allowGet, controller.SSEHandler))
}
