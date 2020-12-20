package api

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
