package api

import "github.com/adi/sketo/db"

// Counters for metrics
var (
	CntRegexPolicies           = int64(0)
	CntGlobPolicies            = int64(0)
	CntExactPolicies           = int64(0)
	CntRegexRoles              = int64(0)
	CntGlobRoles               = int64(0)
	CntExactRoles              = int64(0)
	CntAllowRequestsSinceStart = int64(0)
	CntAllowAcceptedSinceStart = int64(0)
	CntAllowRefusedSinceStart  = int64(0)
	CntAllowFailuresSinceStart = int64(0)
)

// ReloadCounters ..
func ReloadCounters(acpDB *db.DB) error {
	err := acpDB.Count(policyBasePrefix("regex"), policyFilter("", "", ""), func(cnt int64) error {
		CntRegexPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(policyBasePrefix("glob"), policyFilter("", "", ""), func(cnt int64) error {
		CntGlobPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(policyBasePrefix("exact"), policyFilter("", "", ""), func(cnt int64) error {
		CntExactPolicies = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("regex"), roleFilter(""), func(cnt int64) error {
		CntRegexRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("glob"), roleFilter(""), func(cnt int64) error {
		CntGlobRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	err = acpDB.Count(roleBasePrefix("exact"), roleFilter(""), func(cnt int64) error {
		CntExactRoles = cnt
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
