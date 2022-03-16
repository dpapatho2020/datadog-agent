// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package obfuscate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ObfuscateAppSec obfuscates the given appsec tag value in order to remove
// sensitive values from the appsec security events.
func (o *Obfuscator) ObfuscateAppSec(val string) string {
	keyRE := o.opts.AppSec.ParameterKeyRegexp
	valueRE := o.opts.AppSec.ParameterValueRegexp
	if keyRE == nil && valueRE == nil {
		return val
	}
	ob := appsecEventsObfuscator{
		keyRE:   keyRE,
		valueRE: valueRE,
	}
	output, err := ob.obfuscate(val)
	if err != nil {
		o.log.Errorf("unexpected error while obfuscating the appsec events: %v", err)
		return val
	}
	return output
}

type appsecEventsObfuscator struct {
	keyRE, valueRE *regexp.Regexp
}

type unexpectedScannerOpError int

func (err unexpectedScannerOpError) Error() string {
	return fmt.Sprintf("unexpected json scanner operation %d", err)
}

// inputDiff holds the list of diffs, built by the obfuscator, and to ultimately
// apply to the input.
type inputDiff []struct {
	from, to int
	value    string
}

// Add a new entry to the list. Note that due to how the apply() method works
// by creating the output string by walking this list, the list entries must be
// sorted in ascending "input offset" order.
func (d *inputDiff) add(from, to int, value string) {
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

// Apply the diff to the input if any.
func (d inputDiff) apply(input string) string {
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

// Append the given diff to the current one, shifted by the given offset.
// Cf. method obfuscateRuleMatchParameter()
func (d *inputDiff) appendTo(diff *inputDiff, offset int) {
	for _, d := range *d {
		diff.add(d.from+offset, d.to+offset, d.value)
	}
}

// Entrypoint of the appsec obfuscator based on a json scanner and which tries
// to only obfuscate the appsec rule parameters of the given input by searching
// and targeting objects of the form
// `{ "parameters": <appsec rule match parameters>, <any other keys>: <any other values> }`
// When such object is found, its parameters' value is obfuscated.
func (o *appsecEventsObfuscator) obfuscate(input string) (output string, err error) {
	var (
		scanner scanner
		diff    inputDiff
	)
	scanner.reset()
	keyFrom := -1
	keyTo := -1
	// Scan the input to discover its objects and see if they have the
	// `parameters` key we are looking for.
	for i := 0; i < len(input); i++ {
		switch scanner.step(&scanner, input[i]) {
		case scanError:
			return input, scanner.err

		case scanBeginLiteral:
			// Possibly the beginning of an object key
			if input[i] == '"' {
				keyFrom = i
			}
		case scanContinue:
			// Continue the literal value
			if keyFrom != -1 && input[i] == '"' && input[i-1] != '\\' {
				// Ending double-quote found
				keyTo = i
				// Only scanObjetKey will confirm this was an object key
			}
		case scanObjectKey:
			// Object key scanned and keyFrom and keyTo were set according to
			// the previous scanBeginLiteral and scanContinue scanner operations
			if input[keyFrom:keyTo+1] == `"parameters"` {
				i = o.obfuscateRuleMatchParameters(&scanner, input, i+1, &diff)
				i-- // decrement i due to the for loop increment but i is already set to the next byte to scan
			}
			keyFrom = -1
			keyTo = -1
		}
	}
	if scanner.eof() == scanError {
		return input, scanner.err
	}
	return diff.apply(input), nil
}

// Obfuscate the array of parameters of the form `[ <parameter 1>, <...>, <parameter N> ]`.
// The implementation accepts elements of unexpected types.
func (o *appsecEventsObfuscator) obfuscateRuleMatchParameters(scanner *scanner, input string, i int, diff *inputDiff) int {
	i, err := stepTo(scanner, input, i, scanBeginArray)
	if err != nil {
		return i
	}
	for ; i < len(input); i++ {
		i, err = o.obfuscateRuleMatchParameter(scanner, input, i, diff)
		if err != nil {
			if actual, ok := err.(unexpectedScannerOpError); ok {
				if actual == scanEndArray {
					// The previous call failed because we reached the end of the array
					return i
				}
				// Try to step until the next array value
				i, err = stepUntil(scanner, input, i, scanArrayValue)
				if err != nil {
					return i
				}
				continue // Next value reached, and we can proceed trying to obfuscate it
			}
			return i // Abort due to an unexpected error (syntax error or end of json)
		}
		// Step to the beginning of the next array value or end of the array
		var op int
		i, op, err = stepToOneOf(scanner, input, i, scanArrayValue, scanEndArray)
		if err != nil {
			return i
		}
		if op == scanEndArray {
			return i
		}
	}
	return i
}

// Obfuscate the parameter object of the form `{ "key_path": <key path>, "highlight": <highlight>, "value": <value>, <any extra keys>: <any extra values> }`.
// The implementation is permissive so that any extra keys and values are allowed, and permits having any of the three
// keys `key_path`, `highlight` and `value` that we need to obfuscate.
// Note that the overall parameter obfuscation directly depends on the presence of a sensitive key in the key_path.
// As a result, the parameter object needs to be entirely walked to firstly find the key_path.
func (o *appsecEventsObfuscator) obfuscateRuleMatchParameter(scanner *scanner, input string, i int, diff *inputDiff) (int, error) {
	// Walk the object and save the `key_path` value along with the offsets of the
	// `highlight` and `value` values, if any.
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
	// Firstly start by searching for any sensitive key into the key_path
	var hasSensitiveKey bool
	if paramKeyPath != "" {
		hasSensitiveKey = o.hasSensitiveKeyPath(paramKeyPath)
	}
	// Finally, obfuscate the `highlight` and `value` values
	if highlights := input[paramHighlightFrom:paramHighlightTo]; highlights != "" {
		var tmpDiff inputDiff
		o.obfuscateRuleMatchParameterHighlights(highlights, &tmpDiff, hasSensitiveKey)
		tmpDiff.appendTo(diff, paramHighlightFrom)
	}
	if value := input[paramValueFrom:paramValueTo]; value != "" {
		var tmpDiff inputDiff
		o.obfuscateRuleMatchParameterValue(value, &tmpDiff, hasSensitiveKey)
		tmpDiff.appendTo(diff, paramValueFrom)
	}
	return i, nil
}

// Return whether the given key path contains any sensitive key. A key is
// considered sensitive when the key regular expression matches it. It only
// applies to key path elements of string type.
// The expected key path value is of the form `[ <path 1>, <...>, <path N> ]`.
// The implementation is permissive so that any array value type is accepted.
func (o *appsecEventsObfuscator) hasSensitiveKeyPath(keyPath string) (hasSensitiveKey bool) {
	// Shortcut the call if the key regular expression is disabled
	if o.keyRE == nil {
		return false
	}
	// Walk the array values of type string
	walkArrayStrings(keyPath, func(from, to int) {
		// Ignore the call if we already found a sensitive key in a previous call
		if hasSensitiveKey {
			return
		}
		// Unquote the string and check if it matches the key regexp
		value := keyPath[from : to+1]
		value, err := unquote(value)
		if err != nil {
			return
		}
		if o.keyRE.MatchString(value) {
			hasSensitiveKey = true
		}
	})
	return hasSensitiveKey
}

// Obfuscate the parameter's array of highlighted strings of the form `[ <highlight 1>, <...>, <highlight N> ]`.
// If a sensitive key was found, the value regular expression is ignored and every string value of the array is
// obfuscated. It otherwise only obfuscates the sub-strings matching the value regular expression.
// The implementation is permissive so that it accepts any value type and only obfuscates the strings.
// Note that this obfuscator method is a bit different from the others due to the way obfuscateRuleMatchParameter()
// works.
func (o *appsecEventsObfuscator) obfuscateRuleMatchParameterHighlights(input string, diff *inputDiff, hasSensitiveKey bool) {
	// Shortcut the call when the value regular expression is disabled and there
	// is no sensitive key (which acts as a regexp obfuscating everything)
	if o.valueRE == nil && !hasSensitiveKey {
		return
	}
	walkArrayStrings(input, func(from, to int) {
		if hasSensitiveKey {
			diff.add(from, to, `"?"`)
			return
		}
		value, err := unquote(input[from : to+1])
		if err != nil {
			return
		}
		if !o.valueRE.MatchString(value) {
			return
		}
		value = o.valueRE.ReplaceAllString(value, "?")
		value, err = quote(value)
		if err != nil {
			return
		}
		diff.add(from, to, value)
	})
}

// Obfuscate the parameter's value which is expected to be a string. If a
// sensitive key was found, the value regular expression is ignored and the
// entire string value is obfuscated. It otherwise only obfuscates the
// sub-strings matching the value regular expression.
// Note that this obfuscator method is a bit different from the others due to
// the way obfuscateRuleMatchParameter() works.
func (o *appsecEventsObfuscator) obfuscateRuleMatchParameterValue(input string, diff *inputDiff, hasSensitiveKey bool) {
	// Shortcut the call when the value regular expression is disabled and there
	// is no sensitive key (which acts as a regexp obfuscating everything)
	if o.valueRE == nil && !hasSensitiveKey {
		return
	}
	from, to, err := scanString(input)
	if err != nil {
		return
	}
	if hasSensitiveKey {
		diff.add(from, to-1, `"?"`)
		return
	}
	value := input[from:to]
	value, err = unquote(value)
	if err != nil {
		return
	}
	if !o.valueRE.MatchString(value) {
		return
	}
	value = o.valueRE.ReplaceAllString(value, "?")
	value, err = quote(value)
	if err != nil {
		return
	}
	diff.add(from, to-1, value)
}

// Helper function to walk the array elements of type string.
func walkArrayStrings(input string, visit func(from int, to int)) {
	var scanner scanner
	scanner.reset()
	i, err := stepTo(&scanner, input, 0, scanBeginArray)
	if err != nil {
		return
	}
	stringFrom := -1
	depth := 0
	for ; i < len(input); i++ {
		c := input[i]
		switch scanner.step(&scanner, c) {
		case scanBeginObject, scanBeginArray:
			depth++
		case scanEndObject:
			depth--
		case scanEndArray:
			if depth == 0 {
				return
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
			return
		}
	}
}

// Helper function to walk the object keys and values.
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
	scanner.eof()
	return i, scanner.err
}

// Helper function to step to the given expected scanner operation `to`.
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
	scanner.eof()
	return i, scanner.err
}

// Helper function to step to one of the given expected scanner operations `to`.
// An error is returned if another operation is found.
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
	scanner.eof()
	return i, 0, scanner.err
}

// Helper function to keep scanning until the scanner operation `until` is
// reached.
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
	scanner.eof()
	return i, scanner.err
}

// Helper function to scan the string value of the given input. It returns the
// from/to offsets of the input so that the json string is located at
// `input[from:to]`.
func scanString(input string) (from, to int, err error) {
	var scanner scanner
	scanner.reset()
	i, err := stepTo(&scanner, input, 0, scanBeginLiteral)
	if err != nil {
		return 0, 0, err
	}
	from = i - 1
	// Check this is a string literal by checking if the character starting the
	// literal is a double-quote
	if input[from] != '"' {
		return from, i + 1, unexpectedScannerOpError(scanBeginLiteral)
	}
	// Scan the input until we find the double-quote the string
	for ; i < len(input); i++ {
		switch op := scanner.step(&scanner, input[i]); op {
		case scanError:
			return from, i + 1, scanner.err
		case scanContinue:
			// Check if the current character is a double-quote ending the
			// string by checking that it is not escaped by the previous one.
			if input[i] == '"' && input[i-1] != '\\' {
				to := i + 1
				return from, to, nil
			}
		default:
			return from, i + 1, unexpectedScannerOpError(op)
		}
	}
	// We reached the end of the input without finding the last string
	// double-quote and therefore results into a json syntax error.
	scanner.eof()
	return 0, 0, scanner.err
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
