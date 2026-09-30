package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/config"
	"ShadowStat/internal/store"
)

// minPasswordLen mirrors the first-run wizard's policy (internal/config)
// for new accounts created via the web UI.
const minPasswordLen = 12

type userJSON struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}

func toUserJSON(u store.User) userJSON {
	return userJSON{ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt}
}

func (h *apiHandlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *apiHandlers) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Username == "" {
		writeJSONError(w, http.StatusBadRequest, "username_required")
		return
	}
	if len(req.Password) < minPasswordLen {
		writeJSONError(w, http.StatusBadRequest, "password_too_short")
		return
	}
	if req.Role != store.RoleAdmin && req.Role != store.RoleStandard {
		writeJSONError(w, http.StatusBadRequest, "invalid_role")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	id, err := h.db.CreateUser(req.Username, hash, req.Role, time.Now().Unix())
	if err != nil {
		writeJSONError(w, http.StatusConflict, "username_taken")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "ok"})
}

type updateRoleRequest struct {
	Role string `json:"role"`
}

func (h *apiHandlers) updateUserRole(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_user_id")
		return
	}
	var req updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Role != store.RoleAdmin && req.Role != store.RoleStandard {
		writeJSONError(w, http.StatusBadRequest, "invalid_role")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess.UserID == id {
		writeJSONError(w, http.StatusBadRequest, "cannot_change_own_role")
		return
	}

	target, err := h.db.UserByID(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if target.Role == store.RoleAdmin && req.Role != store.RoleAdmin {
		if err := h.guardLastAdmin(w); err != nil {
			return
		}
	}

	if err := h.db.UpdateUserRole(id, req.Role); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *apiHandlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_user_id")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess.UserID == id {
		writeJSONError(w, http.StatusBadRequest, "cannot_delete_own_account")
		return
	}

	target, err := h.db.UserByID(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if target.Role == store.RoleAdmin {
		if err := h.guardLastAdmin(w); err != nil {
			return
		}
	}

	if err := h.db.DeleteUser(id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// guardLastAdmin writes a 400 response and returns a non-nil error if
// removing/demoting the caller's target would leave zero admin accounts —
// which would permanently lock everyone out of settings/user management
// through the UI, with no way back in short of touching the database directly.
func (h *apiHandlers) guardLastAdmin(w http.ResponseWriter) error {
	count, err := h.db.CountAdmins()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return err
	}
	if count <= 1 {
		writeJSONError(w, http.StatusBadRequest, "cannot_remove_last_admin")
		return errLastAdmin
	}
	return nil
}

var errLastAdmin = fmt.Errorf("web: cannot remove the last admin")

func (h *apiHandlers) listInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := config.ListCaptureInterfaces()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": names})
}
