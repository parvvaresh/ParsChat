package middleware

import (
	"net/http"

	"github.com/username/tcp-chat/internal/utils"
)

func EnableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func MethodGuard(allowed map[string]bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		EnableCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if !allowed[r.Method] {
			utils.WriteAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		next(w, r)
	}
}
