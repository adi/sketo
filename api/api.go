package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"

	"github.com/adi/sketo/db"
	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
)

type addOryAccessControlPolicyRoleMembersBody struct {
	Members []string `json:"members"`
}

type authorizationResult struct {
	Allowed bool `json:"allowed"`
}

type healthNotReadyStatus struct {
	Errors map[string]string `json:"errors"`
}

type healthStatus struct {
	Status string `json:"status"`
}

type oryAccessControlPolicy struct {
	Actions     []string               `json:"actions"`
	Conditions  map[string]interface{} `json:"conditions"`
	Description string                 `json:"description"`
	Effect      string                 `json:"effect"`
	ID          string                 `json:"id"`
	Resources   []string               `json:"resources"`
	Subjects    []string               `json:"subjects"`
}

type oryAccessControlPolicyAllowedInput struct {
	Action   string                 `json:"action"`
	Context  map[string]interface{} `json:"context"`
	Resource string                 `json:"resource"`
	Subject  string                 `json:"subject"`
}

type oryAccessControlPolicyRole struct {
	Description string   `json:"description"`
	ID          string   `json:"id"`
	Members     []string `json:"members"`
}

type version struct {
	Version string `json:"version"`
}

func filterDbPrefix(flavor, subject, resource, action string) string {
	return fmt.Sprintf("%s/p/s/%s/r/%s/a/%s/", flavor, subject, resource, action)
}

func idDbPrefix(flavor, subject, resource, action, id string) string {
	return fmt.Sprintf("%s/p/s/%s/r/%s/a/%s/i/%s/", flavor, subject, resource, action, id)
}

func docDbPrefix(flavor, id string) string {
	return fmt.Sprintf("%s/p/i/%s/", flavor, id)
}

// Init sets up the sketo API HTTP endpoints
func Init(apiMux *mux.Router) error {

	// Start ACP DB
	acpDB, err := db.NewDB(path.Join(".", "storage"))
	if err != nil {
		return err
	}

	// Check If a Request is Allowed
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/allowed", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		var body oryAccessControlPolicyAllowedInput
		jsonDec := json.NewDecoder(r.Body)
		err := jsonDec.Decode(&body)
		if err != nil {
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body"))
			return
		}
		spew.Dump(flavor)
		spew.Dump(body)
		rw.Header().Set("Content-Type", "application/json")
		err = acpDB.Get("test", func(value []byte) error {
			rw.WriteHeader(200)
			jsonEnc := json.NewEncoder(rw)
			err := jsonEnc.Encode(authorizationResult{
				Allowed: true,
			})
			if err != nil {
				return err
			}
			// rw.Write(value)
			return nil
		})
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error"))
			return
		}
	}).Methods("POST")

	// listOryAccessControlPolicies
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies", func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]

		var err error
		offsetStr := r.FormValue("offset")
		offset := int64(0)
		if offsetStr != "" {
			offset, err = strconv.ParseInt(offsetStr, 10, 64)
			if err != nil {
				rw.WriteHeader(400)
				rw.Write([]byte("Invalid offset query param\n"))
				return
			}
		}
		limitStr := r.FormValue("limit")
		limit := int64(-1)
		if limitStr != "" {
			limit, err = strconv.ParseInt(limitStr, 10, 64)
			if err != nil {
				rw.WriteHeader(400)
				rw.Write([]byte("Invalid limit query param\n"))
				return
			}
		}
		subject := r.FormValue("subject")
		resource := r.FormValue("resource")
		action := r.FormValue("action")

		err = acpDB.List(filterDbPrefix(flavor, subject, resource, action), offset, limit, func(keys []string, values [][]byte) error {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)
			ret := make([]oryAccessControlPolicy, 0, len(values))
			for _, value := range values {
				var item oryAccessControlPolicy
				err := json.Unmarshal(value, &item)
				if err != nil {
					return err
				}
				ret = append(ret, item)
			}
			jsonEnc := json.NewEncoder(rw)
			return jsonEnc.Encode(ret)
		})
		if err != nil {
			log.Printf("Error listing ACPs: %v\n", err)
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("GET")

	// upsertOryAccessControlPolicy
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		var body oryAccessControlPolicy
		jsonDec := json.NewDecoder(r.Body)
		err := jsonDec.Decode(&body)
		if err != nil {
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body\n"))
			return
		}

		id := body.ID

		// Save doc
		idPrefix := docDbPrefix(flavor, id)
		err = acpDB.Set(idPrefix, body)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Save indexes to doc
		prefixes := make([]string, 0)
		for _, subject := range body.Subjects {
			for _, resource := range body.Resources {
				for _, action := range body.Actions {
					prefixes = append(prefixes, idDbPrefix(flavor, subject, resource, action, id))
				}
				prefixes = append(prefixes, idDbPrefix(flavor, subject, resource, "", id))
			}
		}
		for _, subject := range body.Subjects {
			for _, action := range body.Actions {
				prefixes = append(prefixes, idDbPrefix(flavor, subject, "", action, id))
			}
			prefixes = append(prefixes, idDbPrefix(flavor, subject, "", "", id))
		}
		for _, resource := range body.Resources {
			for _, action := range body.Actions {
				prefixes = append(prefixes, idDbPrefix(flavor, "", resource, action, id))
			}
			prefixes = append(prefixes, idDbPrefix(flavor, "", resource, "", id))
		}
		for _, action := range body.Actions {
			prefixes = append(prefixes, idDbPrefix(flavor, "", "", action, id))
		}
		prefixes = append(prefixes, idDbPrefix(flavor, "", "", "", id))
		err = acpDB.SetBulk(prefixes, idPrefix)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err = jsonEnc.Encode(body)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("PUT")

	// getOryAccessControlPolicy
	// TODO

	// deleteOryAccessControlPolicy
	// TODO

	// List ORY Access Control Policy Roles
	// TODO

	// Upsert an ORY Access Control Policy Role
	// TODO

	// Get an ORY Access Control Policy Role
	// TODO

	// Delete an ORY Access Control Policy Role
	// TODO

	// Add a Member to an ORY Access Control Policy Role
	// TODO

	// Remove a Member From an ORY Access Control Policy Role
	// TODO

	// Check alive status
	apiMux.HandleFunc("/health/alive", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err := jsonEnc.Encode(healthStatus{
			Status: "ok",
		})
		// Alternative return for future use:
		// rw.WriteHeader(500)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
	}).Methods("GET")

	// Check readiness status
	apiMux.HandleFunc("/health/ready", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err := jsonEnc.Encode(healthStatus{
			Status: "ok",
		})
		// Alternative return for future use:
		// rw.WriteHeader(503)
		// err := jsonEnc.Encode(healthNotReadyStatus{
		// 	Errors: map[string]string{
		// 		"database": "Unreachable",
		// 	},
		// })
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
	}).Methods("GET")

	// Get service version
	apiMux.HandleFunc("/version", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("Content-Type", "application/json")
		rw.WriteHeader(200)
		jsonEnc := json.NewEncoder(rw)
		err := jsonEnc.Encode(version{
			Version: "v0.0.1-sketo",
		})
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}
	}).Methods("GET")

	return nil

}
