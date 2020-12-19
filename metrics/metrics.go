package metrics

import (
	"fmt"
	"net/http"

	"github.com/adi/sketo/api"
	"github.com/gorilla/mux"
)

// Init sets up the metrics HTTP endpoints
func Init(metricsMux *mux.Router) error {

	metricsMux.HandleFunc("/metrics", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		rw.Write([]byte(fmt.Sprintf("sketo_policies_total{flavor=\"regex\"} %v\n", api.CntRegexPolicies)))
		rw.Write([]byte(fmt.Sprintf("sketo_policies_total{flavor=\"glob\"} %v\n", api.CntGlobPolicies)))
		rw.Write([]byte(fmt.Sprintf("sketo_policies_total{flavor=\"exact\"} %v\n", api.CntExactPolicies)))
		rw.Write([]byte(fmt.Sprintf("sketo_roles_total{flavor=\"regex\"} %v\n", api.CntRegexRoles)))
		rw.Write([]byte(fmt.Sprintf("sketo_roles_total{flavor=\"glob\"} %v\n", api.CntGlobRoles)))
		rw.Write([]byte(fmt.Sprintf("sketo_roles_total{flavor=\"exact\"} %v\n", api.CntExactRoles)))
		rw.Write([]byte(fmt.Sprintf("sketo_allow_requests_since_start %v\n", api.CntAllowRequestsSinceStart)))
		rw.Write([]byte(fmt.Sprintf("sketo_allow_accepted_since_start %v\n", api.CntAllowAcceptedSinceStart)))
		rw.Write([]byte(fmt.Sprintf("sketo_allow_refused_since_start %v\n", api.CntAllowRefusedSinceStart)))
		rw.Write([]byte(fmt.Sprintf("sketo_allow_failures_since_start %v\n", api.CntAllowFailuresSinceStart)))
	})

	return nil

}
