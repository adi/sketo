package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/adi/sketo/db"
	"github.com/gorilla/mux"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgorilla"
)

// JustAllow ..
var JustAllow bool

// Fix ..
func Fix() error {
	storageDir := path.Join(".", "storage")
	if envVar := os.Getenv("STORAGE_DIR"); envVar != "" {
		storageDir = envVar
	}

	// Start ACP DB
	acpDB, err := db.NewDB(storageDir)
	if err != nil {
		return err
	}

	return acpDB.Fix()
}

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

	// Instrument for APM
	tracer, err := apm.NewTracer(apm.DefaultTracer.Service.Name, apm.DefaultTracer.Service.Version)
	if err != nil {
		return err
	}
	tracer.SetCaptureBody(apm.CaptureBodyAll)
	apiMux.Use(apmgorilla.Middleware(apmgorilla.WithTracer(tracer)))

	// Add endpoint for deleting everything
	apiMux.HandleFunc("/engines/acp/ory", func(rw http.ResponseWriter, r *http.Request) {
		err := acpDB.DelEverything()
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

	// Add endpoint for deleting everything
	apiMux.HandleFunc("/engines/acp/ory/exact/reindex", func(rw http.ResponseWriter, r *http.Request) {
		flavor := "exact"
		err := acpDB.DelByPrefix(policyBasePrefix(flavor) + "s/")
		if err != nil {
			log.Printf("Error deleting by prefix of ACP indexes: %v\n", err)
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
		i := 0
		err = acpDB.Enumerate(policyBasePrefix(flavor), func(key string, value []byte) (bool, error) {
			i++
			if i%10000 == 0 {
				log.Printf("Reindexed %d\n", i)
			}
			var err error
			var item oryAccessControlPolicy
			err = json.Unmarshal(value, &item)
			if err != nil {
				return false, err
			}
			id := item.ID

			// Save indexes to doc
			suffixes := make([]string, 0)
			for _, subject := range item.Subjects {
				for _, resource := range item.Resources {
					for _, action := range item.Actions {
						suffixes = append(suffixes, policySuffix(subject, resource, action, id))
					}
					suffixes = append(suffixes, policySuffix(subject, resource, "", id))
				}
				for _, action := range item.Actions {
					suffixes = append(suffixes, policySuffix(subject, "", action, id))
				}
				suffixes = append(suffixes, policySuffix(subject, "", "", id))
			}
			for _, resource := range item.Resources {
				for _, action := range item.Actions {
					suffixes = append(suffixes, policySuffix("", resource, action, id))
				}
				suffixes = append(suffixes, policySuffix("", resource, "", id))
			}
			for _, action := range item.Actions {
				suffixes = append(suffixes, policySuffix("", "", action, id))
			}
			suffixes = append(suffixes, policySuffix("", "", "", id))
			err = acpDB.RefMany(policyBasePrefix(flavor), suffixes)
			if err != nil {
				return false, err
			}

			return true, nil
		})
		if err != nil {
			log.Printf("Error listing ACPs: %v\n", err)
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
		log.Printf("Done reindexing\n")

	}).Methods("POST")

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
			Version: "v0.4.2",
		})
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
	}).Methods("GET")

	return nil

}
