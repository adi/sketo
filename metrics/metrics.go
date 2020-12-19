package metrics

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Init sets up the metrics HTTP endpoints
func Init(metricsMux *mux.Router) error {

	metricsMux.HandleFunc("/metrics", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		rw.Write([]byte(fmt.Sprintf("acps %v\n", 17)))
	})

	return nil

}
