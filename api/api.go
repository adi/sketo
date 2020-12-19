package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/adi/sketo/db"
	"github.com/google/uuid"
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

func docSuffix(id string) string {
	return fmt.Sprintf("i/%s/", id)
}

func policyBasePrefix(flavor string) string {
	return fmt.Sprintf("%s/po/", flavor)
}

func policyFilter(subject, resource, action string) string {
	return fmt.Sprintf("s/%s/r/%s/a/%s/", subject, resource, action)
}

func policySuffix(subject, resource, action, id string) string {
	return fmt.Sprintf("s/%s/r/%s/a/%s/i/%s/", subject, resource, action, id)
}

func roleBasePrefix(flavor string) string {
	return fmt.Sprintf("%s/ro/", flavor)
}

func roleFilter(member string) string {
	return fmt.Sprintf("m/%s/", member)
}

func roleSuffix(member, id string) string {
	return fmt.Sprintf("m/%s/i/%s/", member, id)
}

// TestPolicies ..
func TestPolicies() {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}
	for i := 0; i < 5000; i++ {

		if i%100 == 0 {
			log.Printf("UPSERT: %d\n", i)
		}
		item := oryAccessControlPolicy{
			ID:          fmt.Sprintf("%dxxx8ea01-3f24-4e0e-acae-af3501b5c487", i),
			Description: "[Candidate/CV]: Update, View, Delete CV Id=8924317 for candidate Id=4893180",
			Subjects: []string{
				"ejobs:account:id:772f00b6-4151-11eb-8cee-d2eaac4f383e",
			},
			Resources: []string{
				"ejobs:candidate:id:4893180:cvs:id:8924317",
			},
			Actions: []string{
				"view", "update", "delete",
			},
			Effect: "allow",
		}

		body, err := json.Marshal(item)
		if err != nil {
			panic(err)
		}

		req, err := http.NewRequest("PUT", "http://127.0.0.1:4466/engines/acp/ory/exact/policies", bytes.NewBuffer(body))
		req.Header = headers

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			panic(errors.New("Non-200 status"))
		}
	}

}

// TestRoles ..
func TestRoles() {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}
	for i := 0; i < 5000; i++ {

		if i%100 == 0 {
			log.Printf("UPSERT: %d\n", i)
		}
		item := oryAccessControlPolicyRole{
			ID:          fmt.Sprintf("%dxxx8ea01-3f24-4e0e-acae-af3501b5c487", i),
			Description: "[Candidate/CV]: Update, View, Delete CV Id=8924317 for candidate Id=4893180",
			Members: []string{
				"ejobs:account:id:772f00b6-4151-11eb-8cee-d2eaac4f383e",
			},
		}

		body, err := json.Marshal(item)
		if err != nil {
			panic(err)
		}

		req, err := http.NewRequest("PUT", "http://127.0.0.1:4466/engines/acp/ory/exact/roles", bytes.NewBuffer(body))
		req.Header = headers

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			panic(errors.New("Non-200 status"))
		}
	}

}

// Counters for metrics
var (
	CntRegexPolicies           = int64(0)
	CntGlobPolicies            = int64(0)
	CntExactPolicies           = int64(0)
	CntRegexRoles              = int64(0)
	CntGlobRoles               = int64(0)
	CntExactRoles              = int64(0)
	CntAllowRequestsSinceStart = int64(0)
	CntAllowAcceptedSinceStart = int64(0)
	CntAllowRefusedSinceStart  = int64(0)
	CntAllowFailuresSinceStart = int64(0)
)

// ReloadCounters ..
func ReloadCounters(acpDB *db.DB) error {
	err := acpDB.Count(policyBasePrefix("regex"), policyFilter("", "", ""), func(cnt int64) error {
		CntRegexPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(policyBasePrefix("glob"), policyFilter("", "", ""), func(cnt int64) error {
		CntGlobPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(policyBasePrefix("exact"), policyFilter("", "", ""), func(cnt int64) error {
		CntExactPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("regex"), roleFilter(""), func(cnt int64) error {
		CntRegexRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("glob"), roleFilter(""), func(cnt int64) error {
		CntGlobRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("exact"), roleFilter(""), func(cnt int64) error {
		CntExactRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	return nil
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

	err = ReloadCounters(acpDB)
	if err != nil {
		return err
	}

	// Delete everything
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

	// Check If a Request is Allowed
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/allowed", func(rw http.ResponseWriter, r *http.Request) {
		CntAllowRequestsSinceStart++
		if r.Header.Get("Content-Type") != "application/json" {
			CntAllowFailuresSinceStart++
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
			CntAllowFailuresSinceStart++
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body"))
			return
		}

		if body.Subject == "" || body.Resource == "" || body.Action == "" {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(200)
			jsonEnc := json.NewEncoder(rw)
			err := jsonEnc.Encode(authorizationResult{
				Allowed: false,
			})
			if err != nil {
				CntAllowFailuresSinceStart++
				if err != nil {
					rw.WriteHeader(500)
					rw.Write([]byte("Server error"))
					return
				}
			}
			CntAllowRefusedSinceStart++
			return
		}

		err = acpDB.Test(policyBasePrefix(flavor), policyFilter(body.Subject, body.Resource, body.Action), func(allowed bool) error {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(200)
			jsonEnc := json.NewEncoder(rw)
			err := jsonEnc.Encode(authorizationResult{
				Allowed: allowed,
			})
			if err != nil {
				CntAllowFailuresSinceStart++
				return err
			}
			if allowed {
				CntAllowAcceptedSinceStart++
			} else {
				CntAllowRefusedSinceStart++
			}
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

		err = acpDB.List(policyBasePrefix(flavor), policyFilter(subject, resource, action), offset, limit, func(keys []string, values [][]byte) error {
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

		if body.ID == "" {
			genID, err := uuid.NewUUID()
			if err != nil {
				rw.WriteHeader(500)
				rw.Write([]byte("Couldn't generate ID\n"))
				return
			}
			body.ID = genID.String()
		}

		id := body.ID

		// Save doc
		docPrefix := docSuffix(id)
		err = acpDB.Set(policyBasePrefix(flavor), docPrefix, body)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Save indexes to doc
		suffixes := make([]string, 0)
		for _, subject := range body.Subjects {
			for _, resource := range body.Resources {
				for _, action := range body.Actions {
					suffixes = append(suffixes, policySuffix(subject, resource, action, id))
				}
				suffixes = append(suffixes, policySuffix(subject, resource, "", id))
			}
			for _, action := range body.Actions {
				suffixes = append(suffixes, policySuffix(subject, "", action, id))
			}
			suffixes = append(suffixes, policySuffix(subject, "", "", id))
		}
		for _, resource := range body.Resources {
			for _, action := range body.Actions {
				suffixes = append(suffixes, policySuffix("", resource, action, id))
			}
			suffixes = append(suffixes, policySuffix("", resource, "", id))
		}
		for _, action := range body.Actions {
			suffixes = append(suffixes, policySuffix("", "", action, id))
		}
		suffixes = append(suffixes, policySuffix("", "", "", id))
		err = acpDB.RefMany(policyBasePrefix(flavor), suffixes)
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

		switch flavor {
		case "regex":
			CntRegexPolicies++
		case "glob":
			CntGlobPolicies++
		case "exact":
			CntExactPolicies++
		}

	}).Methods("PUT")

	// getOryAccessControlPolicy
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies/{id}", func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		err = acpDB.Get(policyBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)
			rw.Write(value)
			return nil
		})
		if err != nil {
			if err == db.ErrKeyNotFound {
				rw.WriteHeader(404)
				rw.Write([]byte("Not found\n"))
				return
			}
			log.Printf("Error getting ACP: %v\n", err)
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("GET")

	// deleteOryAccessControlPolicy
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/policies/{id}", func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		// Get doc
		var subjects []string
		var resources []string
		var actions []string
		err = acpDB.Get(policyBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			var tmpBody oryAccessControlPolicy
			err := json.Unmarshal(value, &tmpBody)
			if err != nil {
				return fmt.Errorf("Couldn't decode body: %w", err)
			}
			for _, s := range tmpBody.Subjects {
				sbytes := []byte(s)
				scopy := make([]byte, 0, len(sbytes))
				copy(scopy, sbytes)
				subjects = append(subjects, string(scopy))
			}
			for _, r := range tmpBody.Resources {
				rbytes := []byte(r)
				rcopy := make([]byte, 0, len(rbytes))
				copy(rcopy, rbytes)
				resources = append(resources, string(rcopy))
			}
			for _, a := range tmpBody.Actions {
				abytes := []byte(a)
				acopy := make([]byte, 0, len(abytes))
				copy(acopy, abytes)
				actions = append(actions, string(acopy))
			}
			return nil
		})
		deleteRefs := true
		if err != nil {
			if err == db.ErrKeyNotFound {
				deleteRefs = false
			} else {
				log.Printf("Error getting ACP: %v\n", err)
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}
		}

		// Delete doc
		idPrefix := docSuffix(id)
		err = acpDB.Del(policyBasePrefix(flavor), idPrefix)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		if deleteRefs {
			// Delete indexes to doc
			suffixes := make([]string, 0)
			for _, subject := range subjects {
				for _, resource := range resources {
					for _, action := range actions {
						suffixes = append(suffixes, policySuffix(subject, resource, action, id))
					}
					suffixes = append(suffixes, policySuffix(subject, resource, "", id))
				}
				for _, action := range actions {
					suffixes = append(suffixes, policySuffix(subject, "", action, id))
				}
				suffixes = append(suffixes, policySuffix(subject, "", "", id))
			}
			for _, resource := range resources {
				for _, action := range actions {
					suffixes = append(suffixes, policySuffix("", resource, action, id))
				}
				suffixes = append(suffixes, policySuffix("", resource, "", id))
			}
			for _, action := range actions {
				suffixes = append(suffixes, policySuffix("", "", action, id))
			}
			suffixes = append(suffixes, policySuffix("", "", "", id))
			err = acpDB.DelManyRefs(policyBasePrefix(flavor), suffixes)
			if err != nil {
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

			switch flavor {
			case "regex":
				CntRegexPolicies--
			case "glob":
				CntGlobPolicies--
			case "exact":
				CntExactPolicies--
			}

		}

		rw.WriteHeader(204)

	}).Methods("DELETE")

	// List ORY Access Control Policy Roles
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles", func(rw http.ResponseWriter, r *http.Request) {
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
		member := r.FormValue("member")

		err = acpDB.List(roleBasePrefix(flavor), roleFilter(member), offset, limit, func(keys []string, values [][]byte) error {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)
			ret := make([]oryAccessControlPolicyRole, 0, len(values))
			for _, value := range values {
				var item oryAccessControlPolicyRole
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

	// Upsert an ORY Access Control Policy Role
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		var body oryAccessControlPolicyRole
		jsonDec := json.NewDecoder(r.Body)
		err := jsonDec.Decode(&body)
		if err != nil {
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body\n"))
			return
		}

		if body.ID == "" {
			genID, err := uuid.NewUUID()
			if err != nil {
				rw.WriteHeader(500)
				rw.Write([]byte("Couldn't generate ID\n"))
				return
			}
			body.ID = genID.String()
		}

		id := body.ID

		// Save doc
		docPrefix := docSuffix(id)
		err = acpDB.Set(roleBasePrefix(flavor), docPrefix, body)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Save indexes to doc
		suffixes := make([]string, 0)
		for _, member := range body.Members {
			suffixes = append(suffixes, roleSuffix(member, id))
		}
		suffixes = append(suffixes, roleSuffix("", id))
		err = acpDB.RefMany(roleBasePrefix(flavor), suffixes)
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

		switch flavor {
		case "regex":
			CntRegexPolicies++
		case "glob":
			CntGlobPolicies++
		case "exact":
			CntExactPolicies++
		}

	}).Methods("PUT")

	// Get an ORY Access Control Policy Role
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}", func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		err = acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)
			rw.Write(value)
			return nil
		})
		if err != nil {
			if err == db.ErrKeyNotFound {
				rw.WriteHeader(404)
				rw.Write([]byte("Not found\n"))
				return
			}
			log.Printf("Error getting ACP: %v\n", err)
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("GET")

	// Delete an ORY Access Control Policy Role
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}", func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		// Get doc
		var members []string
		err = acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			var tmpBody oryAccessControlPolicyRole
			err := json.Unmarshal(value, &tmpBody)
			if err != nil {
				return fmt.Errorf("Couldn't decode body: %w", err)
			}
			for _, m := range tmpBody.Members {
				mbytes := []byte(m)
				mcopy := make([]byte, 0, len(mbytes))
				copy(mcopy, mbytes)
				members = append(members, string(mcopy))
			}
			return nil
		})
		deleteRefs := true
		if err != nil {
			if err == db.ErrKeyNotFound {
				deleteRefs = false
			} else {
				log.Printf("Error getting ACP: %v\n", err)
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}
		}

		// Delete doc
		idPrefix := docSuffix(id)
		err = acpDB.Del(roleBasePrefix(flavor), idPrefix)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		if deleteRefs {
			// Delete indexes to doc
			suffixes := make([]string, 0)
			for _, member := range members {
				suffixes = append(suffixes, roleSuffix(member, id))
			}
			suffixes = append(suffixes, roleSuffix("", id))
			err = acpDB.DelManyRefs(roleBasePrefix(flavor), suffixes)
			if err != nil {
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

			switch flavor {
			case "regex":
				CntRegexRoles--
			case "glob":
				CntGlobRoles--
			case "exact":
				CntExactRoles--
			}

		}

		rw.WriteHeader(204)

	}).Methods("DELETE")

	// Add Members to an ORY Access Control Policy Role
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}/members", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		var bodyx addOryAccessControlPolicyRoleMembersBody
		jsonDec := json.NewDecoder(r.Body)
		err := jsonDec.Decode(&bodyx)
		if err != nil {
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body\n"))
			return
		}

		// Get doc
		var members []string
		var description string
		err = acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			var tmpBody oryAccessControlPolicyRole
			err := json.Unmarshal(value, &tmpBody)
			if err != nil {
				return fmt.Errorf("Couldn't decode body: %w", err)
			}
			for _, m := range tmpBody.Members {
				mbytes := []byte(m)
				mcopy := make([]byte, 0, len(mbytes))
				copy(mcopy, mbytes)
				members = append(members, string(mcopy))
			}
			dbytes := []byte(tmpBody.Description)
			dcopy := make([]byte, 0, len(dbytes))
			copy(dcopy, dbytes)
			description = string(dcopy)
			return nil
		})

		// Add new members that are not yet members
		var newMembers []string
		for _, newMember := range bodyx.Members {
			skip := false
			for _, oldMember := range members {
				if newMember == oldMember {
					skip = true
					break
				}
			}
			if !skip {
				newMembers = append(newMembers, newMember)
			}
		}
		members = append(members, newMembers...)

		doc := oryAccessControlPolicyRole{
			ID:          id,
			Description: description,
			Members:     members,
		}

		// Save doc
		docPrefix := docSuffix(id)
		err = acpDB.Set(roleBasePrefix(flavor), docPrefix, doc)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Save new indexes to doc
		suffixes := make([]string, 0)
		for _, member := range newMembers {
			suffixes = append(suffixes, roleSuffix(member, id))
		}
		err = acpDB.RefMany(roleBasePrefix(flavor), suffixes)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err = jsonEnc.Encode(doc)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("PUT")

	// Remove a Member From an ORY Access Control Policy Role
	apiMux.HandleFunc("/engines/acp/ory/{flavor:regex|glob|exact}/roles/{id}/members/{member}", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]
		member := params["member"]

		// Get doc
		var members []string
		var description string
		err = acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
			var tmpBody oryAccessControlPolicyRole
			err := json.Unmarshal(value, &tmpBody)
			if err != nil {
				return fmt.Errorf("Couldn't decode body: %w", err)
			}
			for _, m := range tmpBody.Members {
				mbytes := []byte(m)
				mcopy := make([]byte, 0, len(mbytes))
				copy(mcopy, mbytes)
				members = append(members, string(mcopy))
			}
			dbytes := []byte(tmpBody.Description)
			dcopy := make([]byte, 0, len(dbytes))
			copy(dcopy, dbytes)
			description = string(dcopy)
			return nil
		})

		// Add new members that are not yet members
		var removedMembers []string
		for i, oldMember := range members {
			if member == oldMember {
				removedMembers = append(removedMembers, member)
				members = append(members[:i], members[i+1:]...)
				break
			}
		}

		doc := oryAccessControlPolicyRole{
			ID:          id,
			Description: description,
			Members:     members,
		}

		// Save doc
		docPrefix := docSuffix(id)
		err = acpDB.Set(roleBasePrefix(flavor), docPrefix, doc)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Save new indexes to doc
		suffixes := make([]string, 0)
		for _, member := range removedMembers {
			suffixes = append(suffixes, roleSuffix(member, id))
		}
		err = acpDB.DelManyRefs(roleBasePrefix(flavor), suffixes)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err = jsonEnc.Encode(doc)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}).Methods("DELETE")

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
