package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"wolfronixgo/internal/metrics"

	"github.com/gorilla/mux"
)

// MetricsHandler handles metrics API endpoints
type MetricsHandler struct {
	store *metrics.MetricsStore
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(store *metrics.MetricsStore) *MetricsHandler {
	return &MetricsHandler{store: store}
}

// GetClientMetrics returns metrics for a specific client
// GET /api/metrics/client/{clientID}
func (h *MetricsHandler) GetClientMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["clientID"]
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}

	if clientID == "" {
		http.Error(w, `{"error": "client_id is required"}`, http.StatusBadRequest)
		return
	}

	metrics, err := h.store.GetClientMetrics(clientID)
	if err != nil {
		http.Error(w, `{"error": "failed to fetch metrics"}`, http.StatusInternalServerError)
		return
	}

	if metrics == nil {
		http.Error(w, `{"error": "client not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// GetAllMetrics returns metrics for all clients
// GET /api/metrics/clients
func (h *MetricsHandler) GetAllMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.GetAllClientMetrics()
	if err != nil {
		http.Error(w, `{"error": "failed to fetch metrics"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": metrics,
		"count":   len(metrics),
	})
}

// GetMetricsSummary returns aggregate metrics across all clients
// GET /api/metrics/summary
func (h *MetricsHandler) GetMetricsSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := h.store.GetMetricsSummary()
	if err != nil {
		http.Error(w, `{"error": "failed to fetch summary"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// GetClientStats returns detailed statistics for a time range
// GET /api/metrics/client/{clientID}/stats?from=2024-01-01&to=2024-12-31
func (h *MetricsHandler) GetClientStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["clientID"]
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}

	if clientID == "" {
		http.Error(w, `{"error": "client_id is required"}`, http.StatusBadRequest)
		return
	}

	// Parse time range
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	var from, to time.Time
	var err error

	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			from, err = time.Parse(time.RFC3339, fromStr)
			if err != nil {
				http.Error(w, `{"error": "invalid from date format"}`, http.StatusBadRequest)
				return
			}
		}
	} else {
		// Default to 30 days ago
		from = time.Now().AddDate(0, 0, -30)
	}

	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			to, err = time.Parse(time.RFC3339, toStr)
			if err != nil {
				http.Error(w, `{"error": "invalid to date format"}`, http.StatusBadRequest)
				return
			}
		}
	} else {
		to = time.Now()
	}

	stats, err := h.store.GetClientStats(clientID, from, to)
	if err != nil {
		http.Error(w, `{"error": "failed to fetch stats"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// AddUser adds a user to a client
// POST /api/metrics/client/{clientID}/users
func (h *MetricsHandler) AddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = "guest"
	}

	if err := h.store.AddUser(req.ClientID, req.UserID, req.Role); err != nil {
		http.Error(w, `{"error": "failed to add user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"client_id": req.ClientID,
		"user_id":   req.UserID,
		"role":      req.Role,
	})
}

// RemoveUser removes a user from a client
// DELETE /api/metrics/client/{clientID}/users/{userID}
func (h *MetricsHandler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.RemoveUser(req.ClientID, req.UserID); err != nil {
		http.Error(w, `{"error": "failed to remove user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"client_id": req.ClientID,
		"user_id":   req.UserID,
	})
}

// RecordUserLogin records a user login
// POST /api/metrics/login
func (h *MetricsHandler) RecordUserLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.RecordUserLogin(req.ClientID, req.UserID); err != nil {
		http.Error(w, `{"error": "failed to record login"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
	})
}
