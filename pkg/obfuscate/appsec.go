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
	"sort"
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
	errUnexpectedEndOfString = errors.New("unexpected end of appsec event string")
)

type unexpectedScannerOpError int

func (err unexpectedScannerOpError) Error() string {
	return fmt.Sprintf("unexpected json scanner operation %d", err)
}

func (o *appsecEventsObfuscator) obfuscateAppSec(input string) (output string, err error) {
	var (
		scanner scanner
		diff    Diff
	)
	scanner.reset()
	keyFrom := -1
	keyTo := -1
	for i := 0; i < len(input); i++ {
		switch scanner.step(&scanner, input[i]) {
		case scanError:
			return input, scanner.err

		case scanBeginLiteral:
			if input[i] == '"' {
				keyFrom = i
			}
		case scanContinue:
			if keyFrom != -1 && input[i] == '"' && input[i-1] != '\\' {
				keyTo = i
			}
		case scanObjectKey:
			if input[keyFrom:keyTo+1] == `"parameters"` {
				i, _ = o.obfuscateAppSecParameters(&scanner, input, i+1, &diff)
				i--
			}
			keyFrom = -1
			keyTo = -1
		}
	}
	if scanner.eof() == scanError {
		return input, scanner.err
	}
	return diff.Apply(input), nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameters(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i, err
	}
	for ; i < len(input); i++ {
		i, err = o.obfuscateAppSecRuleParameter(scanner, input, i, diff)
		if err != nil {
			if actual, ok := err.(unexpectedScannerOpError); ok {
				if actual == scanEndArray {
					return i, nil
				}
				i, err = stepUntil(scanner, input, i, scanArrayValue)
				if err != nil {
					return i, err
				}
				continue
			}
			return i, err
		}
		var op int
		i, op, err = stepToOneOf(scanner, input, i, scanArrayValue, scanEndArray)
		if err != nil {
			return i, err
		}
		if op == scanEndArray {
			return i, nil
		}
	}
	return i, errUnexpectedEndOfString
}

func (o *appsecEventsObfuscator) obfuscateAppSecRuleParameter(scanner *scanner, input string, i int, diff *Diff) (int, error) {
	var (
		paramKeyPath                         string
		paramValueFrom, paramValueTo         int
		paramHighlightFrom, paramHighlightTo int
	)
	i, err := walkObject(scanner, input, i, func(keyFrom, keyTo int, valueFrom, valueTo int) {
		switch input[keyFrom:keyTo] {
		case `"key_path"`:
			paramKeyPath = input[valueFrom:valueTo]
		case `"value"`:
			paramValueFrom = valueFrom
			paramValueTo = valueTo
		case `"highlight"`:
			paramHighlightFrom = valueFrom
			paramHighlightTo = valueTo
		}
	})
	if err != nil {
		return i, err
	}
	var hasSensitiveKey bool
	if paramKeyPath != "" {
		hasSensitiveKey = o.obfuscateAppSecParameterKeyPath(paramKeyPath)
	}
	if paramHighlight := input[paramHighlightFrom:paramHighlightTo]; paramHighlight != "" {
		o.obfuscateAppSecParameterHighlight(paramHighlight, diff, paramHighlightFrom, hasSensitiveKey)
	}
	if paramValue := input[paramValueFrom:paramValueTo]; paramValue != "" {
		o.obfuscateAppSecParameterValue(paramValue, diff, paramValueFrom, hasSensitiveKey)
	}
	return i, nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterKeyPath(input string) (hasSensitiveKey bool) {
	var scanner scanner
	scanner.reset()
	hasSensitiveKey, _, _ = o.obfuscateAppSecParameterKeyPath_(&scanner, input, 0)
	return
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterKeyPath_(scanner *scanner, input string, i int) (hasSensitiveKey bool, j int, err error) {
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

func (o *appsecEventsObfuscator) obfuscateAppSecParameterHighlight(input string, diff *Diff, diffOffset int, hasSensitiveKey bool) error {
	var (
		scanner scanner
		tmpDiff Diff
	)
	scanner.reset()
	_, err := o.obfuscateAppSecParameterHighlight_(&scanner, input, 0, &tmpDiff, hasSensitiveKey)
	if err != nil {
		return err
	}
	tmpDiff.AppendTo(diff, diffOffset)
	return nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterHighlight_(scanner *scanner, input string, i int, diff *Diff, hasSensitiveKey bool) (int, error) {
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
	elt := struct {
		from  int
		to    int
		value string
	}{
		from:  from,
		to:    to,
		value: value,
	}
	diff := *d
	l := len(diff)
	i := sort.Search(l, func(i int) bool {
		return (*d)[i].to > from
	})
	if i == l {
		*d = append(diff, elt)
		return
	}
	*d = append(diff[:i+1], diff[i:]...)
	(*d)[i] = elt
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

func (d *Diff) AppendTo(diff *Diff, offset int) {
	for _, d := range *d {
		diff.Add(d.from+offset, d.to+offset, d.value)
	}
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
	return i, errUnexpectedEndOfString
}

func walkObject(scanner *scanner, input string, i int, visit func(keyFrom, keyTo, valueFrom, valueTo int)) (int, error) {
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
				visit(keyFrom, keyTo, valueFrom, i)
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
			visit(keyFrom, keyTo, valueFrom, i)
			keyFrom = -1
			keyTo = -1
			valueFrom = -1

		case scanError:
			return i, scanner.err
		}
	}
	return i, errUnexpectedEndOfString
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterValue(input string, diff *Diff, diffOffset int, hasSensitiveKey bool) error {
	var (
		scanner scanner
		tmpDiff Diff
	)
	scanner.reset()
	_, err := o.obfuscateAppSecParameterValue_(&scanner, input, 0, &tmpDiff, hasSensitiveKey)
	if err != nil {
		return err
	}
	tmpDiff.AppendTo(diff, diffOffset)
	return nil
}

func (o *appsecEventsObfuscator) obfuscateAppSecParameterValue_(scanner *scanner, input string, i int, diff *Diff, hasSensitiveKey bool) (int, error) {
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

func stepTo(scanner *scanner, input string, i int, to int) (int, error) {
	for ; i < len(input); i++ {
		switch op := scanner.step(scanner, input[i]); op {
		default:
			return i + 1, unexpectedScannerOpError(op)
		case scanSkipSpace, scanContinue:
			continue
		case scanError:
			return i + 1, scanner.err
		case to:
			return i + 1, nil
		}
	}
	return i, errUnexpectedEndOfString
}

func stepToOneOf(scanner *scanner, input string, i int, to ...int) (j int, op int, err error) {
	for ; i < len(input); i++ {
		switch op := scanner.step(scanner, input[i]); op {
		default:
			for _, to := range to {
				if to == op {
					return i + 1, op, nil
				}
			}
			return i + 1, op, unexpectedScannerOpError(op)
		case scanSkipSpace, scanContinue:
			continue
		case scanError:
			return i + 1, op, scanner.err
		}
	}
	return i, 0, errUnexpectedEndOfString
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
	return i, errUnexpectedEndOfString
}

func scanString(scanner *scanner, input string, i int) (value string, from, j int, err error) {
	i, err = stepTo(scanner, input, i, scanBeginLiteral)
	if err != nil {
		return "", 0, i, err
	}
	from = i - 1
	if input[from] != '"' {
		return "", from, i + 1, unexpectedScannerOpError(scanBeginLiteral)
	}
	for ; i < len(input); i++ {
		switch op := scanner.step(scanner, input[i]); op {
		case scanError:
			return "", from, i + 1, scanner.err
		case scanContinue:
			if input[i] == '"' && input[i-1] != '\\' {
				to := i + 1
				return input[from:to], from, to, nil
			}
		default:
			return "", from, i + 1, unexpectedScannerOpError(op)
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
