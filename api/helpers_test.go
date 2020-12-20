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

func TestKetoRegexMatchNegative(t *testing.T) {

	nonMatchingPairs := map[string]string{
		"users:<[_-]{2,4}><[0-9A-Za-z]+>:likeus": "users:5h4u4d3p3v4c4:likeus",
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
