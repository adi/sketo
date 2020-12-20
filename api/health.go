package api

import (
	"encoding/json"
	"net/http"

	"github.com/adi/sketo/db"
)

func alive(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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
	}
}

func ready(acpDB *db.DB) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
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
	}
}
