package api

import (
	"fmt"
)

func docSuffix(id string) string {
	return fmt.Sprintf("i/%s/", id)
}

func policyBasePrefix(flavor string) string {
	return fmt.Sprintf("%s/po/", flavor)
}

func policyFilter(subject, resource, action string) string {
	return fmt.Sprintf("s/%s/r/%s/a/%s/", subject, resource, action)
}

func policySuffix(subject, resource, action, id string) string {
	return fmt.Sprintf("s/%s/r/%s/a/%s/i/%s/", subject, resource, action, id)
}

func roleBasePrefix(flavor string) string {
	return fmt.Sprintf("%s/ro/", flavor)
}

func roleFilter(member string) string {
	return fmt.Sprintf("m/%s/", member)
}

func roleSuffix(member, id string) string {
	return fmt.Sprintf("m/%s/i/%s/", member, id)
}
