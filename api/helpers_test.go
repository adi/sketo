package api

import (
	"fmt"
	"testing"
)

func TestKetoRegexMatchPositive(t *testing.T) {

	matchingPairs := map[string]string{
		"users:<[_-]{2,4}><[0-9A-Za-z]+>:likeus": "users:-__-5h4u4d3p3v4c4:likeus",
	}

	for alternative, item := range matchingPairs {
		result, err := matchesOne("regex", alternative, item)
		if err != nil {
			t.Error(fmt.Errorf("pattern [%s] and sample [%s] reported error while matching: %w", alternative, item, err))
		}
		if !result {
			t.Error(fmt.Errorf("pattern [%s] not matching sample [%s] but it should", alternative, item))
		}
	}

}

func TestKetoRegexMatchManyPositive(t *testing.T) {

	matchingPairs := map[string][]string{
		"borg": {
			"b<[ao]>rg",
			"j<[oa]>hn",
			"s<[oa]>r<[oa]>h",
		},
	}

	for item, alternatives := range matchingPairs {
		result, err := matchesAny("regex", alternatives, item)
		if err != nil {
			t.Error(fmt.Errorf("patterns [%s] and sample [%s] reported error while matching: %w", alternatives, item, err))
		}
		if !result {
			t.Error(fmt.Errorf("patterns [%s] not matching sample [%s] but it should", alternatives, item))
		}
	}

}

func TestKetoRegexMatchManyNegative(t *testing.T) {

	matchingPairs := map[string][]string{
		"berg": {
			"b<[ao]>rg",
			"j<[oa]>hn",
			"s<[oa]>r<[oa]>h",
		},
	}

	for item, alternatives := range matchingPairs {
		result, err := matchesAny("regex", alternatives, item)
		if err != nil {
			t.Error(fmt.Errorf("patterns [%s] and sample [%s] reported error while matching: %w", alternatives, item, err))
		}
		if result {
			t.Error(fmt.Errorf("patterns [%s] matching sample [%s] but it shouldn't", alternatives, item))
		}
	}

}
func TestKetoRegexMatchNegative(t *testing.T) {

	nonMatchingPairs := map[string]string{
		"users:<[_-]{2,4}><[0-9A-Za-z]+>:likeus":  "users:5h4u4d3p3v4c4:likeus",
		"users:<[_-]{2,4}><[0-9A-Za-z]+>:likeu":   "users:____wdefee:likeus",
		"users:<[_-]{2,4}><[0-9A-Za-z]+>:likeyou": "users:____wdefee:unlikeus",
	}

	for alternative, item := range nonMatchingPairs {
		result, err := matchesOne("regex", alternative, item)
		if err != nil {
			t.Error(fmt.Errorf("regex pattern [%s] and sample [%s] reported error while matching: %w", alternative, item, err))
		}
		if result {
			t.Error(fmt.Errorf("regex pattern [%s] matching sample [%s] but it shouldn't", alternative, item))
		}
	}

}

func TestKetoRegexMatchError(t *testing.T) {

	badPatterns := []string{
		"users:<[_}>:likeus",
	}

	for _, alternative := range badPatterns {
		_, err := matchesOne("regex", alternative, "")
		if err == nil {
			t.Error(fmt.Errorf("regex pattern [%s] didn't report error while being parsed but it should", alternative))
		}
	}

}

func TestKetoGlobMatchPositive(t *testing.T) {

	matchingPairs := map[string]string{
		"users:*:likeus":       "users:aydalluiebwj:likeus",
		"users:{c,s}at:likeus": "users:sat:likeus",
	}

	for alternative, item := range matchingPairs {
		result, err := matchesOne("glob", alternative, item)
		if err != nil {
			t.Error(fmt.Errorf("glob pattern [%s] and sample [%s] reported error while matching: %w", alternative, item, err))
		}
		if !result {
			t.Error(fmt.Errorf("glob pattern [%s] not matching sample [%s] but it should", alternative, item))
		}
	}

}

func TestKetoGlobMatchNegative(t *testing.T) {

	matchingPairs := map[string]string{
		"users:*:likeus":       "users:aydalluiebwj:--likeus",
		"users:{c,s}at:likeus": "users:mat:likeus",
	}

	for alternative, item := range matchingPairs {
		result, err := matchesOne("glob", alternative, item)
		if err != nil {
			t.Error(fmt.Errorf("glob pattern [%s] and sample [%s] reported error while matching: %w", alternative, item, err))
		}
		if result {
			t.Error(fmt.Errorf("glob pattern [%s] matching sample [%s] but it shouldn't", alternative, item))
		}
	}

}

func TestKetoGlobMatchError(t *testing.T) {

	badPatterns := []string{
		"users:[a-a-]:likeus",
	}

	for _, alternative := range badPatterns {
		_, err := matchesOne("glob", alternative, "")
		if err == nil {
			t.Error(fmt.Errorf("glob pattern [%s] didn't report error while being parsed but it should", alternative))
		}
	}

}
