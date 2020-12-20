package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/adi/sketo/db"
	"github.com/gorilla/mux"
)

// Check If a Request is Allowed
func allowed(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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

		err = acpDB.List(policyBasePrefix(flavor), policyFilter(body.Subject, body.Resource, body.Action), 0, -1, func(keys []string, values [][]byte) error {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(200)
			allowed := false
			for _, value := range values {
				var item oryAccessControlPolicy
				err := json.Unmarshal(value, &item)
				if err != nil {
					return err
				}
				if item.Effect == "deny" {
					allowed = false
					break
				} else if item.Effect == "allow" {
					allowed = true
				}
			}
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
	}
}
