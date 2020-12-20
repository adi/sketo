package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/adi/sketo/db"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func listOryAccessControlPolicies(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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

		if flavor == "exact" {
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

		} else {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)

			ret := make([]oryAccessControlPolicy, 0)
			err = acpDB.Enumerate(policyBasePrefix(flavor), func(key string, value []byte) (bool, error) {
				var err error
				var item oryAccessControlPolicy
				err = json.Unmarshal(value, &item)
				if err != nil {
					return false, err
				}
				var include bool
				include, err = matchesAny(flavor, item.Subjects, subject)
				if err != nil {
					return false, err
				}
				if include {
					include, err = matchesAny(flavor, item.Resources, resource)
					if err != nil {
						return false, err
					}
				}
				if include {
					include, err = matchesAny(flavor, item.Actions, action)
					if err != nil {
						return false, err
					}
				}
				if include {
					ret = append(ret, item)
				}
				return true, nil
			})
			if err != nil {
				log.Printf("Error listing ACPs: %v\n", err)
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

			jsonEnc := json.NewEncoder(rw)
			err := jsonEnc.Encode(ret)
			if err != nil {
				log.Printf("Error listing ACPs: %v\n", err)
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

		}
	}
}

func upsertOryAccessControlPolicy(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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

		if flavor == "exact" {
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

	}
}

func upsertOryAccessControlPolicies(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		var bodies []oryAccessControlPolicy
		jsonDec := json.NewDecoder(r.Body)
		err := jsonDec.Decode(&bodies)
		if err != nil {
			rw.WriteHeader(400)
			rw.Write([]byte("Couldn't decode body\n"))
			return
		}

		// Add ids if they were not provided
		for i := range bodies {
			if bodies[i].ID == "" {
				genID, err := uuid.NewUUID()
				if err != nil {
					rw.WriteHeader(500)
					rw.Write([]byte("Couldn't generate ID\n"))
					return
				}
				bodies[i].ID = genID.String()
			}
		}

		// Group docs
		bodiesLen := len(bodies)
		abstractBodies := make([]interface{}, bodiesLen)
		docSuffixes := make([]string, bodiesLen)
		for i, body := range bodies {
			abstractBodies[i] = body
			docSuffixes[i] = docSuffix(body.ID)
		}

		// Save docs
		err = acpDB.SetMany(policyBasePrefix(flavor), docSuffixes, abstractBodies)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		if flavor == "exact" {
			// Group indexes to doc
			suffixes := make([]string, 0)
			for _, body := range bodies {
				id := body.ID
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
			}

			// Save indexes to doc
			err = acpDB.RefMany(policyBasePrefix(flavor), suffixes)
			if err != nil {
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

		}

		switch flavor {
		case "regex":
			CntRegexPolicies += int64(bodiesLen)
		case "glob":
			CntGlobPolicies += int64(bodiesLen)
		case "exact":
			CntExactPolicies += int64(bodiesLen)
		}

		rw.Header().Add("Content-Type", "application/json")
		jsonEnc := json.NewEncoder(rw)
		rw.WriteHeader(200)
		err = jsonEnc.Encode(map[string]interface{}{
			"total_imported": len(bodies),
		})
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

	}
}

func getOryAccessControlPolicy(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		err := acpDB.Get(policyBasePrefix(flavor), docSuffix(id), func(value []byte) error {
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

	}
}

func deleteOryAccessControlPolicy(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		// Get doc
		var subjects []string
		var resources []string
		var actions []string
		err := acpDB.Get(policyBasePrefix(flavor), docSuffix(id), func(value []byte) error {
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
		objectFound := true
		if err != nil {
			if err == db.ErrKeyNotFound {
				objectFound = false
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

		if flavor == "exact" {
			if objectFound {
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
			}
		}

		if objectFound {
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

	}
}
