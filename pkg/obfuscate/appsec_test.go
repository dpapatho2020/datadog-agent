package obfuscate

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObfuscateAppSec(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keyRE, valueRE *regexp.Regexp
		value          string
		expected       string
	}{
		{
			// The key regexp should take precedence over the value regexp and obfuscate the entire values
			name:     "sensitive-key",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["?","?","?"],"value":"?"}]}]}]}`,
		},
		{
			// The key regexp should take precedence over the value regexp and obfuscate the entire values
			name:     "sensitive-key",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  nil,
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["?","?","?"],"value":"?"}]}]}]}`,
		},
		{
			// The key regexp doesn't match and the value regexp does and obfuscates accordingly.
			name:     "sensitive-value",
			keyRE:    nil,
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted ? value 1","highlighted value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "disabled",
			keyRE:    nil,
			valueRE:  nil,
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-empty-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    ``,
			expected: ``,
		},
		{
			name:     "unexpected-json-null-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `null`,
			expected: `null`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `""`,
			expected: `""`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{}`,
			expected: `{}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":"not an array"}`,
			expected: `{"triggers":"not an array"}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":["not a struct"]}`,
			expected: `{"triggers":["not a struct"]}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches": "not an array"}]}`,
			expected: `{"triggers":[{"rule_matches": "not an array"}]}`,
		}, {

			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches": ["not a struct"]}]}`,
			expected: `{"triggers":[{"rule_matches": ["not a struct"]}]}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches": [{"parameters":{}}]}]}`,
			expected: `{"triggers":[{"rule_matches": [{"parameters":{}}]}]}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches": [{"parameters":"not an array"}]}]}`,
			expected: `{"triggers":[{"rule_matches": [{"parameters":"not an array"}]}]}`,
		},
		{
			name:     "unexpected-json-value",
			keyRE:    regexp.MustCompile(`SENSITIVE`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches": [{"parameters":["not a struct"]}]}]}`,
			expected: `{"triggers":[{"rule_matches": [{"parameters":["not a struct"]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values with a bad key_path
		{
			name:     "unexpected-json-value-key-path-missing",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-key-path-bad-type",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":"bad type","highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":"bad type","highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-key-path-null-array",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":null,"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":null,"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-key-path-empty-array",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values in case of bad parameter value
		{
			name:     "unexpected-json-value-parameter-highlight-missing",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-highlight-bad-type",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":"bad type","value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":"bad type","value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-highlight-null-array",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":null,"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":null,"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-highlight-empty-array",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-highlight-empty-array",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[1,"the highlighted SENSITIVE value",[1,2,3]],"value":"the entire SENSITIVE value"}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[1,"the highlighted ? value",[1,2,3]],"value":"the entire ? value"}]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values with a bad parameter value
		{
			name:     "unexpected-json-value-parameter-value-missing",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"]}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"]}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-value-bad-type",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":33}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":33}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-value-null",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":null}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":null}]}]}]}`,
		},
		{
			name:     "unexpected-json-value-parameter-value-empty-string",
			keyRE:    regexp.MustCompile(`k3`),
			valueRE:  regexp.MustCompile(`SENSITIVE`),
			value:    `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":""}]}]}]}`,
			expected: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":""}]}]}]}`,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				AppSec: AppSecConfig{
					ParameterKeyRegexp:   tc.keyRE,
					ParameterValueRegexp: tc.valueRE,
				},
			}
			result := NewObfuscator(cfg).ObfuscateAppSec(tc.value)
			if tc.value == "" {
				require.Equal(t, result, tc.expected)
			} else {
				// Compare the two parsed json values
				var actual interface{}
				err := json.Unmarshal([]byte(result), &actual)
				require.NoError(t, err)
				var expected interface{}
				err = json.Unmarshal([]byte(tc.expected), &expected)
				require.NoError(t, err)
				require.Equal(t, expected, actual)
			}
		})
	}
}

func TestX(t *testing.T) {
	//o := appsecEventsObfuscator{}
	//o.obfuscateAppSec(`{"toto":null,"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE value 1","highlighted SENSITIVE value 2","highlighted SENSITIVE value 3"],"value":"the entire SENSITIVE value"}]}]}]}`)
}

func TestObfuscateAppSecParameterValue(t *testing.T) {
	i := []struct {
		name                          string
		input                         string
		expectedSyntaxError           bool
		expectedUnexpectedTypeError   bool
		expectOutput                  string
		expectedUnexpectedEndOfString bool
	}{
		{
			name:         "one-sensitive-value",
			input:        `"i am a SENSITIVE_VALUE value"`,
			expectOutput: `"i am a ? value"`,
		},
		{
			name:         "many-sensitive-values",
			input:        `"SENSITIVE_VALUE i am a SENSITIVE_VALUE value SENSITIVE_VALUE"`,
			expectOutput: `"? i am a ? value ?"`,
		},
		{
			name:         "many-sensitive-values",
			input:        `"      SENSITIVE_VALUE i am a      SENSITIVE_VALUE value      SENSITIVE_VALUE     "`,
			expectOutput: `"      ? i am a      ? value      ?     "`,
		},
		{
			name:         "no-sensitive-values",
			input:        `"i am just a value"`,
			expectOutput: `"i am just a value"`,
		},
		{
			name:         "empty-json-string",
			input:        `""`,
			expectOutput: `""`,
		},
		{
			name:                          "unterminated-json-string",
			input:                         `"i am a SENSITIVE_VALUE value`,
			expectOutput:                  `"i am a SENSITIVE_VALUE value`,
			expectedUnexpectedEndOfString: true,
		},
		{
			name:                        "empty-string",
			input:                       ``,
			expectOutput:                ``,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "null",
			input:                       `null`,
			expectOutput:                `null`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "object",
			input:                       `{"k":"v"}`,
			expectOutput:                `{"k":"v"}`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "array",
			input:                       `[1,2,"three"]`,
			expectOutput:                `[1,2,"three"]`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "float",
			input:                       `1.5`,
			expectOutput:                `1.5`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                "syntax-error",
			input:               `"i am a SENSITIVE_VALUE \ `,
			expectOutput:        `"i am a SENSITIVE_VALUE \ `,
			expectedSyntaxError: true,
		},
	}
	for _, tc := range i {
		t.Run(tc.name, func(t *testing.T) {
			for _, hasSensitiveKey := range []bool{true, false} {
				var name string
				if hasSensitiveKey {
					name = "with-sensitive-key"
				} else {
					name = "without-sensitive-key"
				}
				t.Run(name, func(t *testing.T) {
					o := appsecEventsObfuscator{
						keyRE:   regexp.MustCompile("SENSITIVE_KEY"),
						valueRE: regexp.MustCompile("SENSITIVE_VALUE"),
					}
					var diff Diff
					scanner := &scanner{}
					scanner.reset()
					_, err := o.obfuscateAppSecParameterValue(scanner, tc.input, 0, &diff, hasSensitiveKey)
					output := diff.Apply(tc.input)
					if err != nil {
						if tc.expectedSyntaxError {
							require.Equal(t, scanner.err, err)
						} else if tc.expectedUnexpectedTypeError {
							require.Equal(t, errUnexpectedType, err)
						} else if tc.expectedUnexpectedEndOfString {
							require.Equal(t, errUnexpectedEndOfString, err)
						} else {
							require.NoError(t, err)
						}
						require.Empty(t, diff)
						require.Equal(t, tc.expectOutput, output)
					} else {
						output := diff.Apply(tc.input)
						if hasSensitiveKey {
							require.Equal(t, `"?"`, output)
						} else {
							require.Equal(t, tc.expectOutput, output)
						}
					}
				})
			}
		})
	}
}

func TestObfuscateAppSecParameterHighlight(t *testing.T) {
	i := []struct {
		name                           string
		input                          string
		expectedSyntaxError            bool
		expectedUnexpectedTypeError    bool
		expectedOutput                 string
		expectedOutputWithSensitiveKey string
		expectedUnexpectedEndOfString  bool
	}{
		{
			name:                           "one-sensitive-value",
			input:                          `["i am a SENSITIVE_VALUE value"]`,
			expectedOutput:                 `["i am a ? value"]`,
			expectedOutputWithSensitiveKey: `["?"]`,
		},
		{
			name:                           "many-sensitive-values",
			input:                          `["SENSITIVE_VALUE i am a SENSITIVE_VALUE value SENSITIVE_VALUE"]`,
			expectedOutput:                 `["? i am a ? value ?"]`,
			expectedOutputWithSensitiveKey: `["?"]`,
		},
		{
			name:                           "many-sensitive-values",
			input:                          `["      SENSITIVE_VALUE i am a      SENSITIVE_VALUE value      SENSITIVE_VALUE     "]`,
			expectedOutput:                 `["      ? i am a      ? value      ?     "]`,
			expectedOutputWithSensitiveKey: `["?"]`,
		},
		{
			name:                           "no-sensitive-values",
			input:                          `["i am just a value"]`,
			expectedOutput:                 `["i am just a value"]`,
			expectedOutputWithSensitiveKey: `["?"]`,
		},
		{
			name:                           "empty-array",
			input:                          `[]`,
			expectedOutput:                 `[]`,
			expectedOutputWithSensitiveKey: `[]`,
		},
		{
			name:                           "empty-json-string",
			input:                          `[""]`,
			expectedOutput:                 `[""]`,
			expectedOutputWithSensitiveKey: `["?"]`,
		},
		{
			name:                          "unterminated-json-string",
			input:                         `["i am a SENSITIVE_VALUE value`,
			expectedOutput:                `["i am a SENSITIVE_VALUE value`,
			expectedUnexpectedEndOfString: true,
		},
		{
			name:                        "empty-string",
			input:                       ``,
			expectedOutput:              ``,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "null",
			input:                       `null`,
			expectedOutput:              `null`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "object",
			input:                       `{}`,
			expectedOutput:              `{}`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "float",
			input:                       `1.5`,
			expectedOutput:              `1.5`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                "syntax-error",
			input:               `["i am a SENSITIVE_VALUE \ `,
			expectedOutput:      `["i am a SENSITIVE_VALUE \ `,
			expectedSyntaxError: true,
		},
	}
	for _, tc := range i {
		t.Run(tc.name, func(t *testing.T) {
			for _, hasSensitiveKey := range []bool{true, false} {
				var name string
				if hasSensitiveKey {
					name = "with-sensitive-key"
				} else {
					name = "without-sensitive-key"
				}
				t.Run(name, func(t *testing.T) {
					o := appsecEventsObfuscator{
						keyRE:   regexp.MustCompile("SENSITIVE_KEY"),
						valueRE: regexp.MustCompile("SENSITIVE_VALUE"),
					}
					var diff Diff
					scanner := &scanner{}
					scanner.reset()
					_, err := o.obfuscateAppSecParameterHighlight(scanner, tc.input, 0, &diff, hasSensitiveKey)
					output := diff.Apply(tc.input)
					if err != nil {
						if tc.expectedSyntaxError {
							require.Equal(t, scanner.err, err)
						} else if tc.expectedUnexpectedTypeError {
							require.Equal(t, errUnexpectedType, err)
						} else if tc.expectedUnexpectedEndOfString {
							require.Equal(t, errUnexpectedEndOfString, err)
						} else {
							require.NoError(t, err)
						}
						require.Empty(t, diff)
						require.Equal(t, tc.expectedOutput, output)
					} else {
						output := diff.Apply(tc.input)
						if hasSensitiveKey {
							require.Equal(t, tc.expectedOutputWithSensitiveKey, output)
						} else {
							require.Equal(t, tc.expectedOutput, output)
						}
					}
				})
			}
		})
	}
}

func TestObfuscateAppSecParameterKeyPath(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		input                       string
		expectedSyntaxError         bool
		expectedUnexpectedTypeError bool
		expectedSensitiveKey        bool
	}{
		{
			name:                 "flat",
			input:                `[]`,
			expectedSensitiveKey: false,
		},
		{
			name:                 "flat",
			input:                `[1,2,3,"four","SENSITIVE_KEY",5]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "flat-first",
			input:                `[    "SENSITIVE_KEY"   , 1,2,3,"four" , 5]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "flat-middle",
			input:                `[    "SENSITIVE_KEY"   ]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "flat-last",
			input:                `[ 1,2,3,"four" , 5   ,      "SENSITIVE_KEY"   ]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "flat",
			input:                `[1,2,3,"four",5]`,
			expectedSensitiveKey: false,
		},
		{
			name:                 "sub-array",
			input:                `[1,2,3,"four","SENSITIVE_KEY",5, [ "SENSITIVE_KEY" ], 6]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "sub-array",
			input:                `[1,2,3,"four",5, [ "SENSITIVE_KEY" ], 6]`,
			expectedSensitiveKey: false,
		},
		{
			name:                 "sub-array",
			input:                `[1,2,3,"four",5, [[[]]], "SENSITIVE_KEY", 6]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "sub-object",
			input:                `[1,2,3,"four",5, { "a": "b" }, 6]`,
			expectedSensitiveKey: false,
		},
		{
			name:                 "mixed",
			input:                `[1,2,3,"four",5, { "key_path": [ "SENSITIVE_KEY" ] }, 6]`,
			expectedSensitiveKey: false,
		},
		{
			name:                 "mixed",
			input:                `[1,2.2,3,"four",5, [ { "key_path": [ "SENSITIVE_KEY" ] } ], [{},[{},[{},[{},[{},[{}]]]]]], "SENSITIVE_KEY", 6]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "mixed",
			input:                `["SENSITIVE_KEY", 1,2,3,"four",5, [ { "key_path": [ "SENSITIVE_KEY" ] } ], [{},[{},[{},[{},[{},[{}]]]]]], "SENSITIVE_KEY", 6]`,
			expectedSensitiveKey: true,
		},
		{
			name:                 "mixed",
			input:                `[ 1,2,3,"four",5, [ { "key_path": [ "SENSITIVE_KEY" ] } ], [{},[{},[{},[{},[{},[{}]]]]]], "SENSITIVE_KEY", 6]`,
			expectedSensitiveKey: true,
		},
		{
			name:                "syntax-error",
			input:               `[ 1,2,3,"four",5, [ { "key_path": [ "SENSITIVE_KEY" ] } ], [{},[{},[{},[{},[{},[{}]]]]]], "SENSITIVE_KEY" 6]`,
			expectedSyntaxError: true,
		},
		{
			name:                "syntax-error",
			input:               `[ 1,2,3,"four",5, [ { [ "SENSITIVE_KEY" ] } ], [{},[{},[{},[{},[{},[{}]]]]]], "SENSITIVE_KEY", 6]`,
			expectedSyntaxError: true,
		},
		{
			name:                        "null",
			input:                       `null`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "object",
			input:                       `{}`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                        "unterminated",
			input:                       `[ "SENSITIVE_KEY"`,
			expectedUnexpectedTypeError: true,
		},
		{
			name:                "syntax-error",
			input:               `[ "SENSITIVE_KEY"" ]`,
			expectedSyntaxError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := appsecEventsObfuscator{
				keyRE:   regexp.MustCompile("SENSITIVE_KEY"),
				valueRE: regexp.MustCompile("SENSITIVE_VALUE"),
			}
			scanner := &scanner{}
			scanner.reset()
			hasSensitiveKey, i, err := o.obfuscateAppSecParameterKeyPath(scanner, tc.input, 0)
			if tc.expectedSyntaxError {
				require.Equal(t, scanner.err, err)
			} else if tc.expectedUnexpectedTypeError {
				require.Equal(t, errUnexpectedType, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.input), i)
			}
			require.Equal(t, tc.expectedSensitiveKey, hasSensitiveKey)
		})
	}
}

func TestWalkObject(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		input                       string
		expectedSeen                map[string]string
		expectedSyntaxError         bool
		expectedUnexpectedTypeError bool
	}{
		{
			name:         "flat",
			input:        `{}`,
			expectedSeen: map[string]string{},
		},
		{
			name:         "flat",
			input:        `{   "key"      :    "  value  "   }`,
			expectedSeen: map[string]string{`"key"`: `    "  value  "   `},
		},
		{
			name:         "flat",
			input:        `{   "key 1"      :    "  value 1  "  ,    "key 2"      :    "  value 2  "  ,  "key 3"      :    "  value 3  "   }`,
			expectedSeen: map[string]string{`"key 1"`: `    "  value 1  "  `, `"key 2"`: `    "  value 2  "  `, `"key 3"`: `    "  value 3  "   `},
		},
		{
			name:         "flat",
			input:        `{"key":"  value  "}`,
			expectedSeen: map[string]string{`"key"`: `"  value  "`},
		},
		{
			name:         "flat",
			input:        `{"key":["  value  "]}`,
			expectedSeen: map[string]string{`"key"`: `["  value  "]`},
		},
		{
			name:         "flat",
			input:        `{"key":      [      "  value  "   ]      }`,
			expectedSeen: map[string]string{`"key"`: `      [      "  value  "   ]      `},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := &scanner{}
			scanner.reset()
			seen := map[string]string{}
			i, err := walkObject(scanner, tc.input, 0, func(key, value string) {
				assert.NotContains(t, seen, key)
				seen[key] = value
			})
			if tc.expectedSyntaxError {
				require.Equal(t, scanner.err, err)
			} else if tc.expectedUnexpectedTypeError {
				require.Equal(t, errUnexpectedType, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.input), i)
				require.Equal(t, tc.expectedSeen, seen)
			}
		})
	}
}
