package api

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
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

type position struct {
	start int
	end   int
}

type ketoRegexStringPart struct {
	pos   *position
	regex bool
}

type ketoRegexStringMatcher struct {
	literal *string
	regex   *regexp.Regexp
}

func ketoRegexStringToParts(ketoRegexString string) []ketoRegexStringPart {
	ketoRegexRunes := []rune(ketoRegexString)
	var parts []ketoRegexStringPart
	inRegex := false
	lastPos := 0
	for pos, c := range ketoRegexRunes {
		if inRegex {
			if c == '>' { // end of regex
				inRegex = false
				if pos > lastPos+1 {
					parts = append(parts, ketoRegexStringPart{
						pos: &position{
							start: lastPos + 1,
							end:   pos,
						},
						regex: true,
					})
					lastPos = pos + 1
				}
			}
		} else {
			if c == '<' { // end of string
				inRegex = true
				if pos > lastPos {
					parts = append(parts, ketoRegexStringPart{
						pos: &position{
							start: lastPos,
							end:   pos,
						},
						regex: false,
					})
					lastPos = pos
				}
			}
		}
	}
	if lastPos < len(ketoRegexRunes)-1 { // end of last string
		parts = append(parts, ketoRegexStringPart{
			pos: &position{
				start: lastPos,
				end:   len(ketoRegexRunes),
			},
			regex: false,
		})
	}
	return parts
}

func ketoRegexStringPartsToMatchers(src []rune, parts []ketoRegexStringPart) ([]ketoRegexStringMatcher, error) {
	var matchers []ketoRegexStringMatcher
	for _, part := range parts {
		srcPart := string(src[part.pos.start:part.pos.end])
		if part.regex {
			r, err := regexp.Compile(srcPart)
			if err != nil {
				return nil, err
			}
			matchers = append(matchers, ketoRegexStringMatcher{
				regex: r,
			})
		} else {
			matchers = append(matchers, ketoRegexStringMatcher{
				literal: &srcPart,
			})
		}
	}
	return matchers, nil
}

var ketoGlobStringMatcherCache map[string]glob.Glob = make(map[string]glob.Glob)
var ketoRegexStringMatcherCache map[string][]ketoRegexStringMatcher = make(map[string][]ketoRegexStringMatcher)

func matchesOne(flavor string, alternative string, item string) (bool, error) {
	if flavor == "glob" {
		var gp glob.Glob
		if cachedGp, ok := ketoGlobStringMatcherCache[alternative]; ok {
			gp = cachedGp
		} else {
			var err error
			gp, err = glob.Compile(alternative, ':')
			if err != nil {
				return false, err
			}
			ketoGlobStringMatcherCache[alternative] = gp
		}
		return gp.Match(item), nil
	} else if flavor == "regex" {
		var matchers []ketoRegexStringMatcher
		if cachedMatchers, ok := ketoRegexStringMatcherCache[alternative]; ok {
			matchers = cachedMatchers
		} else {
			var err error
			matchers, err = ketoRegexStringPartsToMatchers([]rune(alternative), ketoRegexStringToParts(alternative))
			if err != nil {
				return false, err
			}
			ketoRegexStringMatcherCache[alternative] = matchers
		}
		pos := 0
		for _, matcher := range matchers {
			itemRemaining := string([]rune(item)[pos:])
			if matcher.literal != nil {
				if strings.HasPrefix(itemRemaining, *matcher.literal) {
					pos += len([]rune(*matcher.literal))
				} else {
					return false, nil
				}
			} else if matcher.regex != nil {
				matched := matcher.regex.FindString(itemRemaining)
				if matched != "" {
					pos += len([]rune(matched))
				} else {
					return false, nil
				}
			}
		}
		if pos < len(item) {
			return false, nil
		}
		return true, nil
	}
	return false, errors.New("Unknown flavor")
}

func matchesAny(flavor string, alternatives []string, item string) (bool, error) {
	for _, alternative := range alternatives {
		r, err := matchesOne(flavor, alternative, item)
		if err != nil {
			return false, err
		}
		if r {
			return true, nil
		}
	}
	return false, nil
}
