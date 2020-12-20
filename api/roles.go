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

func listOryAccessControlPolicyRoles(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
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

	}
}

func upsertOryAccessControlPolicyRole(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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
			CntRegexRoles++
		case "glob":
			CntGlobRoles++
		case "exact":
			CntExactRoles++
		}

	}
}

func upsertOryAccessControlPolicyRoles(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(400)
			rw.Write([]byte(fmt.Sprintf(`Bad request (content type "%s" not allowed on this endpoint; only "application/json" is valid)`, r.Header.Get("Content-Type"))))
			return
		}
		params := mux.Vars(r)
		flavor := params["flavor"]
		var bodies []oryAccessControlPolicyRole
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
		err = acpDB.SetMany(roleBasePrefix(flavor), docSuffixes, abstractBodies)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		// Group indexes to doc
		suffixes := make([]string, 0)
		for _, body := range bodies {
			id := body.ID
			for _, member := range body.Members {
				suffixes = append(suffixes, roleSuffix(member, id))
			}
			suffixes = append(suffixes, roleSuffix("", id))
		}

		// Save indexes to doc
		err = acpDB.RefMany(roleBasePrefix(flavor), suffixes)
		if err != nil {
			rw.WriteHeader(500)
			rw.Write([]byte("Server error\n"))
			return
		}

		switch flavor {
		case "regex":
			CntRegexRoles += int64(bodiesLen)
		case "glob":
			CntGlobRoles += int64(bodiesLen)
		case "exact":
			CntExactRoles += int64(bodiesLen)
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

func getOryAccessControlPolicyRole(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		err := acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
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

func deleteOryAccessControlPolicyRole(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		flavor := params["flavor"]
		id := params["id"]

		// Get doc
		var members []string
		err := acpDB.Get(roleBasePrefix(flavor), docSuffix(id), func(value []byte) error {
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

	}
}
