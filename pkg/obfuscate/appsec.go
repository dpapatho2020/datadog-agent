// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package obfuscate

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ObfuscateAppSec obfuscates the given appsec tag value in order to remove sensitive values from the appsec security
// events. The tag value should be of the form `{"triggers":<appsec events>}` and follow the JSON schema defined at
// https://github.com/DataDog/libddwaf/blob/1.0.17/schema/appsec-event-1.0.0.json
func (o *Obfuscator) ObfuscateAppSec(val string) string {
	keyRE := o.opts.AppSec.ParameterKeyRegexp
	valueRE := o.opts.AppSec.ParameterValueRegexp
	if keyRE == nil && valueRE == nil {
		return val
	}

	var appsecMeta interface{}
	if err := json.Unmarshal([]byte(val), &appsecMeta); err != nil {
		o.log.Errorf("Could not parse the appsec span tag as a json value: %s", err)
		return val
	}

	meta, ok := appsecMeta.(map[string]interface{})
	if !ok {
		return val
	}

	triggers, ok := meta["triggers"].([]interface{})
	if !ok {
		return val
	}

	var sensitiveDataFound bool
	for _, trigger := range triggers {
		trigger, ok := trigger.(map[string]interface{})
		if !ok {
			continue
		}
		ruleMatches, ok := trigger["rule_matches"].([]interface{})
		if !ok {
			continue
		}
		for _, ruleMatch := range ruleMatches {
			ruleMatch, ok := ruleMatch.(map[string]interface{})
			if !ok {
				continue
			}
			parameters, ok := ruleMatch["parameters"].([]interface{})
			if !ok {
				continue
			}
			for _, param := range parameters {
				param, ok := param.(map[string]interface{})
				if !ok {
					continue
				}

				paramValue, hasStrValue := param["value"].(string)
				highlight, _ := param["highlight"].([]interface{})
				keyPath, _ := param["key_path"].([]interface{})

				var sensitiveKeyFound bool
				for _, key := range keyPath {
					str, ok := key.(string)
					if !ok {
						continue
					}
					if !matchString(keyRE, str) {
						continue
					}
					sensitiveKeyFound = true
					for i, v := range highlight {
						if _, ok := v.(string); ok {
							highlight[i] = "?"
						}
					}
					if hasStrValue {
						param["value"] = "?"
					}
					break
				}

				if sensitiveKeyFound {
					sensitiveDataFound = true
					continue
				}

				// Obfuscate the parameter value
				if hasStrValue && matchString(valueRE, paramValue) {
					sensitiveDataFound = true
					param["value"] = valueRE.ReplaceAllString(paramValue, "?")
				}

				// Obfuscate the parameter highlights
				for i, h := range highlight {
					h, ok := h.(string)
					if !ok {
						continue
					}
					if matchString(valueRE, h) {
						sensitiveDataFound = true
						highlight[i] = valueRE.ReplaceAllString(h, "?")
					}
				}
			}
		}
	}

	if !sensitiveDataFound {
		return val
	}

	newVal, err := json.Marshal(appsecMeta)
	if err != nil {
		o.log.Errorf("Could not marshal the obfuscated appsec span tag into a json value: %s", err)
		return val
	}
	return string(newVal)
}

func matchString(re *regexp.Regexp, s string) bool {
	if re == nil {
		return false
	}
	return re.MatchString(s)
}

type appsecEventsObfuscator struct {
	keyRE, valueRE *regexp.Regexp
}

var (
	errUnexpectedType        = errors.New("unexpected appsec event type")
	errUnexpectedEndOfString = errors.New("unexpected end of appsec event string")
)

func (o *appsecEventsObfuscator) obfuscateKeyPath(scanner *scanner, input string, i *int, output strings.Builder, keyRE *regexp.Regexp) (sensitiveKey bool, err error) {
	if scanner.step(scanner, input[*i]) != scanBeginArray {
		return false, errUnexpectedType
	}
	*i++
	depth := 0
	literalFrom := 0
loop:
	for {
		c := input[*i]
		op := scanner.step(scanner, c)
		switch op {
		case scanBeginObject, scanBeginArray:
			depth++

		case scanEndObject:
			depth--

		case scanEndArray:
			depth--
			if depth == 0 {
				break loop
			}

		case scanBeginLiteral, scanContinue:
			if depth == 0 && literalFrom == -1 {
				literalFrom = *i
			}

		case scanArrayValue:
			value, err := strconv.Unquote(input[literalFrom:*i])
			if err != nil {
				continue
			}
			if matchString(keyRE, value) {
				sensitiveKey = true
				break
			}

		case scanError:
			return false, scanner.err
		}
		*i++
	}
	return sensitiveKey, nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecTriggers(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i, err
	}
	for i += 1; i < len(input); i++ {
		i, err = o.obfuscateAppSecTrigger(scanner, input, i, diff)
		if err == errUnexpectedType {
			i, err = stepUntil(scanner, input, i, scanArrayValue)
			if err != nil {
				return i, err
			}
			continue
		}
		if err != nil {
			return i, err
		}
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecTrigger(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginObject)
	if err != nil {
		return i, err
	}
	var (
		key string
	)
	for i += 1; i < len(input); i++ {
		key, i, err = scannObjectKey(scanner, input, i)
		if err == errUnexpectedType {
			i, err = stepUntil(scanner, input, i, scanObjectValue)
			if err != nil {
				return i, err
			}
			continue
		}
		if err != nil {
			return i, err
		}
		if key == "rule_matches" {
			i, err = o.obfuscateAppSecRuleMatches(scanner, input, i, diff)
			if err == errUnexpectedType {
				i, err = stepUntil(scanner, input, i, scanObjectValue)
				if err != nil {
					return i, err
				}
				continue
			}
			if err != nil {
				return i, err
			}
		}
		i, err = stepObjectValue(scanner, input, i)
		if err != nil && err != errUnexpectedType {
			return i, err
		}
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecRuleMatches(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i, err
	}
	for i += 1; i < len(input); i++ {
		i, err = o.obfuscateAppSecRuleMatch(scanner, input, i, diff)
		if err == errUnexpectedType {
			i, err = stepUntil(scanner, input, i, scanArrayValue)
			if err != nil {
				return i, err
			}
			continue
		}
		if err != nil {
			return i, err
		}
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecRuleMatch(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginObject)
	if err != nil {
		return i, err
	}
	var (
		key string
	)
	for i += 1; i < len(input); i++ {
		key, i, err = scannObjectKey(scanner, input, i)
		if err == errUnexpectedType {
			i, err = stepUntil(scanner, input, i, scanObjectValue)
			if err != nil {
				return i, err
			}
			continue
		}
		if err != nil {
			return i, err
		}
		if key == "parameters" {
			i, err = o.obfuscateAppSecRuleParameters(scanner, input, i, diff)
			if err == errUnexpectedType {
				i, err = stepUntil(scanner, input, i, scanObjectValue)
				if err != nil {
					return i, err
				}
				continue
			}
			if err != nil {
				return i, err
			}
		}
		i, err = stepObjectValue(scanner, input, i)
		if err != nil && err != errUnexpectedType {
			return i, err
		}
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecRuleParameters(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i, err
	}
	for i += 1; i < len(input); i++ {
		i, err = o.obfuscateAppSecRuleParameter(scanner, input, i, diff)
		if err == errUnexpectedType {
			i, err = stepUntil(scanner, input, i, scanArrayValue)
			if err != nil {
				return i, err
			}
			continue
		}
		if err != nil {
			return i, err
		}
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecRuleParameter(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	return i, nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterKeyPath(scanner *scanner, input string, i int) (hasSensitiveKey bool, j int, err error) {
	i, err = obfuscateArrayStrings(scanner, input, i, func(from, to int) {
		// Ignore the call if we already found a sensitive key in a previous call
		if hasSensitiveKey {
			return
		}
		value := input[from : to+1]
		value, err := unquote(value)
		if err != nil {
			return
		}
		if matchString(o.keyRE, value) {
			hasSensitiveKey = true
		}
	})
	if err != nil {
		return false, i, err
	}
	return hasSensitiveKey, i, nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterHighlight(scanner *scanner, input string, i int, diff *Diff, hasSensitiveKey bool) (int, error) {
	i, err := obfuscateArrayStrings(scanner, input, i, func(from, to int) {
		if hasSensitiveKey {
			diff.Add(from, to, `"?"`)
			return
		}
		value, err := unquote(input[from : to+1])
		if err != nil {
			return
		}
		if !matchString(o.valueRE, value) {
			return
		}
		value = o.valueRE.ReplaceAllString(value, "?")
		value, err = quote(value)
		if err != nil {
			return
		}
		diff.Add(from, to, value)
	})
	if err != nil {
		return i, err
	}
	return i, nil
}

type Diff []struct {
	from, to int
	value    string
}

func (d *Diff) Add(from, to int, value string) {
	*d = append(*d, struct {
		from  int
		to    int
		value string
	}{from, to, value})
}

func (d Diff) Apply(input string) string {
	from := 0
	var output strings.Builder
	for _, diff := range d {
		output.WriteString(input[from:diff.from])
		from = diff.to + 1
		output.WriteString(diff.value)
	}
	output.WriteString(input[from:])
	return output.String()
}

func obfuscateArrayStrings(scanner *scanner, input string, i int, visit func(from, to int)) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i, err
	}
	stringFrom := -1
	depth := 0
	for ; i < len(input); i++ {
		c := input[i]
		switch scanner.step(scanner, c) {
		case scanBeginObject, scanBeginArray:
			depth++
		case scanEndObject:
			depth--
		case scanEndArray:
			if depth == 0 {
				return i + 1, nil
			}
			depth--

		case scanBeginLiteral:
			if depth == 0 && input[i] == '"' {
				stringFrom = i
			}
		case scanContinue:
			if stringFrom != -1 && input[i] == '"' && input[i-1] != '\\' {
				visit(stringFrom, i)
				stringFrom = -1
			}

		case scanError:
			return i, scanner.err
		}
	}
	if stringFrom != -1 {
		return i, errUnexpectedEndOfString
	}
	return i, errUnexpectedType
}

func walkObject(scanner *scanner, input string, i int, visit func(key, value string)) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginObject)
	if err != nil {
		return i, err
	}
	keyFrom := -1
	keyTo := -1
	valueFrom := -1
	depth := 0
	for ; i < len(input); i++ {
		switch scanner.step(scanner, input[i]) {
		case scanBeginObject, scanBeginArray:
			depth++
		case scanEndArray:
			depth--
		case scanEndObject:
			if depth != 0 {
				depth--
				continue
			}
			// We reached the end of the object we were scanning
			if keyFrom != -1 && keyTo != -1 && valueFrom != -1 {
				// Visit the last value of the objet
				visit(input[keyFrom:keyTo], input[valueFrom:i])
			}
			return i + 1, nil

		case scanBeginLiteral:
			if depth != 0 || keyFrom != -1 {
				continue
			}
			if input[i] == '"' {
				keyFrom = i
			}
		case scanContinue:
			if keyFrom != -1 && keyTo == -1 && input[i] == '"' && input[i-1] != '\\' {
				keyTo = i + 1
			}

		case scanObjectKey:
			if depth == 0 {
				valueFrom = i + 1
			}
		case scanObjectValue:
			if depth != 0 {
				continue
			}
			visit(input[keyFrom:keyTo], input[valueFrom:i])
			keyFrom = -1
			keyTo = -1
			valueFrom = -1

		case scanError:
			return i, scanner.err
		}
	}
	if keyFrom != -1 || valueFrom != -1 || i == len(input) {
		return i, errUnexpectedEndOfString
	}
	return i, errUnexpectedType
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterValue(scanner *scanner, input string, i int, diff *Diff, hasSensitiveKey bool) (int, error) {
	value, from, i, err := scanString(scanner, input, i)
	if err != nil {
		return i, err
	}
	if hasSensitiveKey {
		diff.Add(from, i-1, `"?"`)
		return i, nil
	}
	value, err = unquote(value)
	if err != nil {
		return i, err
	}
	if !matchString(o.valueRE, value) {
		return i, nil
	}
	value = o.valueRE.ReplaceAllString(value, "?")
	value, err = quote(value)
	if err != nil {
		return i, err
	}
	diff.Add(from, i-1, value)
	return i, nil
}

func scannObjectKey(scanner *scanner, input string, i int) (key string, j int, err error) {
	i, err = stepTo(scanner, input, i, scanBeginLiteral)
	if err != nil {
		return "", i, err
	}
	from := i
	for i += 1; i < len(input); i++ {
		switch scanner.step(scanner, input[i]) {
		case scanError:
			return "", i, scanner.err
		case scanObjectKey:
			value, err := strconv.Unquote(input[from:i])
			if err != nil {
				return "", i, err
			}
			return value, i + 1, nil
		case scanEndObject:
			return "", i + 1, nil
		}
	}
	return "", i, errUnexpectedType
}

func stepObjectValue(scanner *scanner, input string, i int) (j int, err error) {
	return stepUntil(scanner, input, i, scanObjectValue)
}

func stepTo(scanner *scanner, input string, i int, to int) (int, error) {
	for ; i < len(input); i++ {
		switch scanner.step(scanner, input[i]) {
		default:
			return i + 1, errUnexpectedType
		case scanSkipSpace, scanContinue:
			continue
		case scanError:
			return i + 1, scanner.err
		case to:
			return i + 1, nil
		}
	}
	return i, errUnexpectedType
}

func stepUntil(scanner *scanner, input string, i int, until int) (int, error) {
	for ; i < len(input); i++ {
		switch op := scanner.step(scanner, input[i]); op {
		case scanError:
			return i + 1, scanner.err
		case scanSkipSpace, scanContinue:
			continue
		case until:
			return i + 1, nil
		}
	}
	return i, errUnexpectedType
}

func stepUntilEndObjectString(scanner *scanner, input string, i int) (j int, delim string, err error) {
	for ; i < len(input); i++ {
		op := scanner.step(scanner, input[i])
		fmt.Println(op)
		switch op {
		case scanError:
			return i + 1, "", scanner.err
		case scanSkipSpace, scanContinue:
			continue
		case scanEndObject:
			return i + 1, "", nil
		case scanObjectValue:
			return i + 1, ",", nil
		}
	}
	return i, "", errUnexpectedType
}

func scanString(scanner *scanner, input string, i int) (value string, from, j int, err error) {
	i, err = stepTo(scanner, input, i, scanBeginLiteral)
	if err != nil {
		return "", 0, i, err
	}
	from = i - 1
	if input[from] != '"' {
		return "", from, i + 1, errUnexpectedType
	}
	for ; i < len(input); i++ {
		switch scanner.step(scanner, input[i]) {
		case scanError:
			return "", from, i + 1, scanner.err
		case scanContinue:
			if input[i] == '"' && input[i-1] != '\\' {
				to := i + 1
				return input[from:to], from, to, nil
			}
		default:
			return "", from, i + 1, errUnexpectedType
		}
	}
	return "", from, i, errUnexpectedEndOfString
}

// unquote converts a quoted JSON string literal into a Go string.
// The JSON quoting rules are different from Go's, so strconv.Unquote cannot
// be used.
func unquote(s string) (t string, err error) {
	err = json.Unmarshal([]byte(s), &t)
	return t, err
}

// quote converts a Go string into a quoted JSON string literal.
// The rules are different from Go's string quoting, so strconv.Unquote cannot
// be used.
func quote(s string) (t string, err error) {
	buf, err := json.Marshal(s)
	return string(buf), err
}
