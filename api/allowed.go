package api

import (
	"encoding/json"
	"fmt"
	"log"
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

		if flavor == "exact" {
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

		} else {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(200)

			allowed := false

			err = acpDB.Enumerate(policyBasePrefix(flavor), func(key string, value []byte) (bool, error) {
				var err error
				var item oryAccessControlPolicy
				err = json.Unmarshal(value, &item)
				if err != nil {
					return false, err
				}
				var include bool
				include, err = matchesAny(flavor, item.Subjects, body.Subject)
				if err != nil {
					return false, err
				}
				if include {
					include, err = matchesAny(flavor, item.Resources, body.Resource)
					if err != nil {
						return false, err
					}
				}
				if include {
					include, err = matchesAny(flavor, item.Actions, body.Action)
					if err != nil {
						return false, err
					}
				}
				if include {
					if item.Effect == "deny" {
						allowed = false
						return false, nil
					} else if item.Effect == "allow" {
						allowed = true
					}
				}
				return true, nil
			})
			if err != nil {
				log.Printf("Error checking ACPs: %v\n", err)
				rw.WriteHeader(500)
				rw.Write([]byte("Server error\n"))
				return
			}

			jsonEnc := json.NewEncoder(rw)
			err := jsonEnc.Encode(authorizationResult{
				Allowed: allowed,
			})
			if err != nil {
				CntAllowFailuresSinceStart++
				if err != nil {
					log.Printf("Error checking ACPs: %v\n", err)
					rw.WriteHeader(500)
					rw.Write([]byte("Server error\n"))
					return
				}
			}
			if allowed {
				CntAllowAcceptedSinceStart++
			} else {
				CntAllowRefusedSinceStart++
			}

		}
	}
}
