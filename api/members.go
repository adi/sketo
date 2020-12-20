package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/adi/sketo/db"
	"github.com/gorilla/mux"
)

func addMembersToAccessControlPolicyRole(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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

	}
}

func removeMemberFromAccessControlPolicyRole(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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

	}
}
