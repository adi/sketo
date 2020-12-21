package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path"

	"github.com/adi/sketo/db"
	"github.com/gorilla/mux"
)

// JustAllow ..
var JustAllow bool

// Init sets up the sketo API HTTP endpoints
func Init(apiMux *mux.Router) error {

	// Load from ENV the location of the DB
	storageDir := path.Join(".", "storage")
	if envVar := os.Getenv("STORAGE_DIR"); envVar != "" {
		storageDir = envVar
	}

	// Start ACP DB
	acpDB, err := db.NewDB(storageDir)
	if err != nil {
		return err
	}

	// Initialize metric counters
	err = ReloadCounters(acpDB)
	if err != nil {
		return err
	}

	// Add endpoint for deleting everything
	apiMux.HandleFunc("/engines/acp/ory", func(rw http.ResponseWriter, r *http.Request) {
		err = acpDB.DelEverything()
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error"))
			return
		}
		err = ReloadCounters(acpDB)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error"))
			return
		}
	}).Methods("DELETE")

	// Policies endpoints
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/allowed", allowed(acpDB)).Methods("POST")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies", listOryAccessControlPolicies(acpDB)).Methods("GET")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies", upsertOryAccessControlPolicy(acpDB)).Methods("PUT")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies/batch", upsertOryAccessControlPolicies(acpDB)).Methods("PUT")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies/{id}", getOryAccessControlPolicy(acpDB)).Methods("GET")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies/{id}", deleteOryAccessControlPolicy(acpDB)).Methods("DELETE")

	// Roles endpoints
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles", listOryAccessControlPolicyRoles(acpDB)).Methods("GET")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles", upsertOryAccessControlPolicyRole(acpDB)).Methods("PUT")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/batch", upsertOryAccessControlPolicyRoles(acpDB)).Methods("PUT")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}", getOryAccessControlPolicyRole(acpDB)).Methods("GET")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}", deleteOryAccessControlPolicyRole(acpDB)).Methods("DELETE")

	// Member endpoints
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}/members", addMembersToAccessControlPolicyRole(acpDB)).Methods("PUT")
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}/members/{member}", removeMemberFromAccessControlPolicyRole(acpDB)).Methods("DELETE")

	// Health endpoints
	apiMux.HandleFunc("/health/alive", alive(acpDB)).Methods("GET")
	apiMux.HandleFunc("/health/ready", ready(acpDB)).Methods("GET")

	// Get service version
	apiMux.HandleFunc("/version", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("Content-Type", "application/json")
		rw.WriteHeader(200)
		jsonEnc := json.NewEncoder(rw)
		err := jsonEnc.Encode(version{
			Version: "v0.2.1",
		})
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
	}).Methods("GET")

	return nil

}
