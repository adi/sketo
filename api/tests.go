package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// TestPolicies ..
func TestPolicies() {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}

	batchSize := 5000
	batchCount := 100
	dispayMultiplier := 2

	var items []oryAccessControlPolicy
	for j := 0; j < batchSize; j++ {
		item := oryAccessControlPolicy{
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
		items = append(items, item)
	}

	body, err := json.Marshal(items)
	if err != nil {
		panic(err)
	}

	for i := 0; i < batchSize*batchCount; i += batchSize {

		if i%(batchSize*dispayMultiplier) == 0 {
			log.Printf("UPSERT: %d\n", i)
		}

		req, err := http.NewRequest("PUT", "http://127.0.0.1:4466/engines/acp/ory/exact/policies/batch", bytes.NewBuffer(body))
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

	batchSize := 5000
	batchCount := 100
	dispayMultiplier := 2

	var items []oryAccessControlPolicyRole
	for j := 0; j < batchSize; j++ {
		item := oryAccessControlPolicyRole{
			Description: "[Candidate/CV]: Update, View, Delete CV Id=8924317 for candidate Id=4893180",
			Members: []string{
				"ejobs:account:id:772f00b6-4151-11eb-8cee-d2eaac4f383e",
			},
		}
		items = append(items, item)
	}

	body, err := json.Marshal(items)
	if err != nil {
		panic(err)
	}

	for i := 0; i < batchSize*batchCount; i += batchSize {

		if i%(batchSize*dispayMultiplier) == 0 {
			log.Printf("UPSERT: %d\n", i)
		}

		req, err := http.NewRequest("PUT", "http://127.0.0.1:4466/engines/acp/ory/exact/roles/batch", bytes.NewBuffer(body))
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
