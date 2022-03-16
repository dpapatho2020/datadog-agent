package obfuscate

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObfuscateAppSec(t *testing.T) {
	i := []struct {
		name                string
		input               string
		expectedOutput      string
		expectedSyntaxError bool
	}{
		{
			name:           "object-empty",
			input:          `{}`,
			expectedOutput: `{}`,
		},
		{
			name:           "object-no-parameters",
			input:          `{ " key 1 " : " value 1 " }`,
			expectedOutput: `{ " key 1 " : " value 1 " }`,
		},
		{
			name:           "object-parameters-last",
			input:          `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" } ] }`,
			expectedOutput: `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a ? value with many ?" } ] }`,
		},
		{
			name:           "object-parameters-alone",
			input:          `{ "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" } ] }`,
			expectedOutput: `{ "parameters" : [ { "value": "i am a ? value with many ?" } ] }`,
		},
		{
			name:           "object-parameters-first",
			input:          `{ "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" } ] , " key 1 " : " value 1 " }`,
			expectedOutput: `{ "parameters" : [ { "value": "i am a ? value with many ?" } ] , " key 1 " : " value 1 " }`,
		},
		{
			name:           "object-parameters-middle",
			input:          `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" } ] , " key 2 " : " value 2 " }`,
			expectedOutput: `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a ? value with many ?" } ] , " key 2 " : " value 2 " }`,
		},
		{
			name:           "object-many-parameters",
			input:          `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " }`,
			expectedOutput: `{ " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a ? value with many ?" }, { "value": " i am the second ? ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth ? ! " } ] , " key 2 " : " value 2 " }`,
		},
		{
			name:           "object-nested",
			input:          `{ "triggers" : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
			expectedOutput: `{ "triggers" : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a ? value with many ?" }, { "value": " i am the second ? ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth ? ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
		},
		{
			name:                "syntax-error-unexpected-end-of-json",
			input:               `{ "triggers" : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ]`,
			expectedOutput:      `{ "triggers" : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ]`,
			expectedSyntaxError: true,
		},
		{
			name:                "syntax-error-unexpected-string-escape",
			input:               `{ "triggers\ " : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
			expectedOutput:      `{ "triggers\ " : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
			expectedSyntaxError: true,
		},
		{
			name:                "syntax-error",
			input:               `{ "triggers : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
			expectedOutput:      `{ "triggers : [ { "rule_matches" : [ { " key 1 " : " value 1 " , "parameters" : [ { "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }, { "value": " i am the second SENSITIVE_VALUE ! " }, { "value": " i am the third value ! " }, { "value": " i am the forth SENSITIVE_VALUE ! " } ] , " key 2 " : " value 2 " } ] } ] }`,
			expectedSyntaxError: true,
		},

		{
			// The key regexp should take precedence over the value regexp and obfuscate the entire values
			name:           "sensitive-key",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"SENSITIVE_KEY"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"SENSITIVE_KEY"],"highlight":["?","?","?"],"value":"?"}]}]}]}`,
		},
		{
			// The key regexp should take precedence over the value regexp and obfuscate the entire values
			name:           "sensitive-key",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["?","?","?"],"value":"?"}]}]}]}`,
		},
		{
			// The key regexp doesn't match and the value regexp does and obfuscates accordingly.
			name:           "sensitive-value",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,"k1",2,"k3"],"highlight":["highlighted ? value 1","highlighted value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-empty-value",
			input:          ``,
			expectedOutput: ``,
		},
		{
			name:           "unexpected-json-null-value",
			input:          `null`,
			expectedOutput: `null`,
		},
		{
			name:           "unexpected-json-value",
			input:          `""`,
			expectedOutput: `""`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{}`,
			expectedOutput: `{}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":"not an array"}`,
			expectedOutput: `{"triggers":"not an array"}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":["not a struct"]}`,
			expectedOutput: `{"triggers":["not a struct"]}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":[{"rule_matches": "not an array"}]}`,
			expectedOutput: `{"triggers":[{"rule_matches": "not an array"}]}`,
		}, {

			name:           "unexpected-json-value",
			input:          `{"triggers":[{"rule_matches": ["not a struct"]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches": ["not a struct"]}]}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":[{"rule_matches": [{"parameters":{}}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches": [{"parameters":{}}]}]}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":[{"rule_matches": [{"parameters":"not an array"}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches": [{"parameters":"not an array"}]}]}`,
		},
		{
			name:           "unexpected-json-value",
			input:          `{"triggers":[{"rule_matches": [{"parameters":["not a struct"]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches": [{"parameters":["not a struct"]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values with a bad key_path
		{
			name:           "unexpected-json-value-key-path-missing",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-key-path-bad-type",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":"bad type","highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":"bad type","highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-key-path-null-array",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":null,"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":null,"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-key-path-empty-array",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":"the entire ? value"}]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values in case of bad parameter value
		{
			name:           "unexpected-json-value-parameter-highlight-missing",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-highlight-bad-type",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":"bad type","value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":"bad type","value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-highlight-null-array",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":null,"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":null,"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-highlight-empty-array",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[],"value":"the entire ? value"}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-highlight-empty-array",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[1,"the highlighted SENSITIVE_VALUE value",[1,2,3]],"value":"the entire SENSITIVE_VALUE value"}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":[1,"the highlighted ? value",[1,2,3]],"value":"the entire ? value"}]}]}]}`,
		},
		// The obfuscator should be permissive enough to still obfuscate the values with a bad parameter value
		{
			name:           "unexpected-json-value-parameter-value-missing",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"]}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"]}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-value-bad-type",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":33}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":33}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-value-null",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":null}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":null}]}]}]}`,
		},
		{
			name:           "unexpected-json-value-parameter-value-empty-string",
			input:          `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted SENSITIVE_VALUE value 1","highlighted SENSITIVE_VALUE value 2","highlighted SENSITIVE_VALUE value 3"],"value":""}]}]}]}`,
			expectedOutput: `{"triggers":[{"rule_matches":[{"parameters":[{"key_path":[0,1,2,"3"],"highlight":["highlighted ? value 1","highlighted ? value 2","highlighted ? value 3"],"value":""}]}]}]}`,
		},
	}
	for _, tc := range i {
		t.Run(tc.name, func(t *testing.T) {
			o := appsecEventsObfuscator{
				keyRE:   regexp.MustCompile("SENSITIVE_KEY"),
				valueRE: regexp.MustCompile("SENSITIVE_VALUE"),
			}
			output, err := o.obfuscateAppSec(tc.input)
			if err != nil {
				if tc.expectedSyntaxError {
					_, ok := err.(*SyntaxError)
					require.True(t, ok)
				} else {
					require.NoError(t, err)
				}
			}
			require.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestObfuscateAppSecParameter(t *testing.T) {
	i := []struct {
		name                          string
		input                         string
		expectedOutput                string
		expectedSyntaxError           bool
		unexpectedScannerOpError      int
		expectedUnexpectedEndOfString bool
	}{
		{
			name:           "value-alone",
			input:          `{ "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" }`,
			expectedOutput: `{ "value": "i am a ? value with many ?" }`,
		},
		{
			name:           "highlight-alone",
			input:          `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ] }`,
			expectedOutput: `{ "highlight": [ "i am a ? value", "i am not a a sensitive value", "i am another ? value" ] }`,
		},
		{
			name:           "sensitive-values-without-key-path",
			input:          `{ "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ] }`,
			expectedOutput: `{ "value": "i am a ? value with many ?", "highlight": [ "i am a ? value", "i am not a a sensitive value", "i am another ? value" ] }`,
		},
		{
			name:           "sensitive-values",
			input:          `{ "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key_path": ["key"] }`,
			expectedOutput: `{ "value": "i am a ? value with many ?", "highlight": [ "i am a ? value", "i am not a a sensitive value", "i am another ? value" ], "key_path": ["key"] }`,
		},
		{
			name:           "sensitive-key-last",
			input:          `{ "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"] }`,
			expectedOutput: `{ "value": "?", "highlight": [ "?", "?", "?" ], "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"] }`,
		},
		{
			name:           "sensitive-key-middle",
			input:          `{ "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"], "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ] }`,
			expectedOutput: `{ "value": "?", "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"], "highlight": [ "?", "?", "?" ] }`,
		},
		{
			name:           "sensitive-key-first",
			input:          `{ "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ] }`,
			expectedOutput: `{ "key_path": ["key", 0, 1, 2, "SENSITIVE_KEY"], "value": "?", "highlight": [ "?", "?", "?" ] }`,
		},
		{
			name:           "empty-object",
			input:          `{  }`,
			expectedOutput: `{  }`,
		},
		{
			name:           "empty-object",
			input:          `{}`,
			expectedOutput: `{}`,
		},
		{
			name:           "object-other-properties",
			input:          `{ "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
			expectedOutput: `{ "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
		},
		{
			name:           "object-mixed-properties",
			input:          `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["key"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
			expectedOutput: `{ "highlight": [ "i am a ? value", "i am not a a sensitive value", "i am another ? value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["key"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a ? value with many ?", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
		},
		{
			name:           "object-mixed-properties-sensitive-key",
			input:          `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
			expectedOutput: `{ "highlight": [ "?", "?", "?" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "?", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null }`,
		},
		{
			name:           "object-mixed-no-spaces",
			input:          `{"highlight":["i am a SENSITIVE_VALUE value","i am not a a sensitive value","i am another SENSITIVE_VALUE value"],"key 1":"SENSITIVE_VALUE","key_path":["SENSITIVE_KEY"],"key 2":["SENSITIVE_VALUE"],"value":"i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE","key 3":{"SENSITIVE_KEY":"SENSITIVE_VALUE"},"SENSITIVE_KEY":null}`,
			expectedOutput: `{"highlight":["?","?","?"],"key 1":"SENSITIVE_VALUE","key_path":["SENSITIVE_KEY"],"key 2":["SENSITIVE_VALUE"],"value":"?","key 3":{"SENSITIVE_KEY":"SENSITIVE_VALUE"},"SENSITIVE_KEY":null}`,
		},
		{
			name:           "object-mixed-properties-sensitive-key-with-bad-value-types",
			input:          `{ "highlight": "bad type - i am a SENSITIVE_VALUE value", "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "value": [ "bad type - i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" ], "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": ["SENSITIVE_VALUE"], "key_path": ["SENSITIVE_KEY"] }`,
			expectedOutput: `{ "highlight": "bad type - i am a SENSITIVE_VALUE value", "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "value": [ "bad type - i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE" ], "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": ["SENSITIVE_VALUE"], "key_path": ["SENSITIVE_KEY"] }`,
		},
		{
			name:           "object-mixed-properties-sensitive-key-having-bad-type",
			input:          `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null, "key_path": "bad type - SENSITIVE_KEY" }`,
			expectedOutput: `{ "highlight": [ "i am a ? value", "i am not a a sensitive value", "i am another ? value" ], "key 1": "SENSITIVE_VALUE", "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a ? value with many ?", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null, "key_path": "bad type - SENSITIVE_KEY" }`,
		},
		{
			name:                          "unterminated-json",
			input:                         `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null`,
			expectedOutput:                `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": null`,
			expectedUnexpectedEndOfString: true,
		},
		{
			name:                "syntax-error",
			input:               `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": i`,
			expectedOutput:      `{ "highlight": [ "i am a SENSITIVE_VALUE value", "i am not a a sensitive value", "i am another SENSITIVE_VALUE value" ], "key 1": "SENSITIVE_VALUE", "key_path": ["SENSITIVE_KEY"], "key 2": [ "SENSITIVE_VALUE" ], "value": "i am a SENSITIVE_VALUE value with many SENSITIVE_VALUE", "key 3": { "SENSITIVE_KEY": "SENSITIVE_VALUE" }, "SENSITIVE_KEY": i`,
			expectedSyntaxError: true,
		},
	}
	for _, tc := range i {
		t.Run(tc.name, func(t *testing.T) {
			o := appsecEventsObfuscator{
				keyRE:   regexp.MustCompile("SENSITIVE_KEY"),
				valueRE: regexp.MustCompile("SENSITIVE_VALUE"),
			}
			var diff Diff
			scanner := &scanner{}
			scanner.reset()
			_, err := o.obfuscateAppSecRuleParameter(scanner, tc.input, 0, &diff)
			output := diff.Apply(tc.input)
			if err != nil {
				if tc.expectedSyntaxError {
					require.Equal(t, scanner.err, err)
				} else if tc.unexpectedScannerOpError != 0 {
					require.Equal(t, tc.unexpectedScannerOpError, err)
				} else if tc.expectedUnexpectedEndOfString {
					require.Equal(t, errUnexpectedEndOfString, err)
				} else {
					require.NoError(t, err)
				}
				require.Empty(t, diff)
				require.Equal(t, tc.expectedOutput, output)
			} else {
				output := diff.Apply(tc.input)
				require.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}

func TestObfuscateAppSecParameterValue(t *testing.T) {
	i := []struct {
		name                          string
		input                         string
		expectedSyntaxError           bool
		unexpectedScannerOpError      bool
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
			name:                     "empty-string",
			input:                    ``,
			expectOutput:             ``,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "null",
			input:                    `null`,
			expectOutput:             `null`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "object",
			input:                    `{"k":"v"}`,
			expectOutput:             `{"k":"v"}`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "array",
			input:                    `[1,2,"three"]`,
			expectOutput:             `[1,2,"three"]`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "float",
			input:                    `1.5`,
			expectOutput:             `1.5`,
			unexpectedScannerOpError: true,
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
					_, err := o.obfuscateAppSecParameterValue_(scanner, tc.input, 0, &diff, hasSensitiveKey)
					output := diff.Apply(tc.input)
					if err != nil {
						if tc.expectedSyntaxError {
							require.Equal(t, scanner.err, err)
						} else if tc.unexpectedScannerOpError {
							require.Equal(t, tc.unexpectedScannerOpError, err)
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
		unexpectedScannerOpError       bool
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
			name:                     "empty-string",
			input:                    ``,
			expectedOutput:           ``,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "null",
			input:                    `null`,
			expectedOutput:           `null`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "object",
			input:                    `{}`,
			expectedOutput:           `{}`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "float",
			input:                    `1.5`,
			expectedOutput:           `1.5`,
			unexpectedScannerOpError: true,
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
					_, err := o.obfuscateAppSecParameterHighlight_(scanner, tc.input, 0, &diff, hasSensitiveKey)
					output := diff.Apply(tc.input)
					if err != nil {
						if tc.expectedSyntaxError {
							require.Equal(t, scanner.err, err)
						} else if tc.unexpectedScannerOpError {
							require.Equal(t, tc.unexpectedScannerOpError, err)
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
		name                     string
		input                    string
		expectedSyntaxError      bool
		unexpectedScannerOpError bool
		expectedSensitiveKey     bool
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
			name:                     "null",
			input:                    `null`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "object",
			input:                    `{}`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "unterminated",
			input:                    `[ "SENSITIVE_KEY"`,
			unexpectedScannerOpError: true,
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
			hasSensitiveKey, i, err := o.obfuscateAppSecParameterKeyPath_(scanner, tc.input, 0)
			if tc.expectedSyntaxError {
				require.Equal(t, scanner.err, err)
			} else if tc.unexpectedScannerOpError {
				require.Equal(t, tc.unexpectedScannerOpError, err)
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
		name                               string
		input                              string
		expectedSeen                       map[string]string
		expectedSyntaxError                bool
		unexpectedScannerOpError           bool
		expectedUnexpectedEndOfStringError bool
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
			name:         "nested-last-array",
			input:        `{"key":["  value  "]}`,
			expectedSeen: map[string]string{`"key"`: `["  value  "]`},
		},
		{
			name:         "nested-last-array",
			input:        `{"key":      [      "  value  "   ]      }`,
			expectedSeen: map[string]string{`"key"`: `      [      "  value  "   ]      `},
		},
		{
			name:         "nested-arrays",
			input:        `{"key 1":      [      "  value 1  "   ]      ,  "key 2":      [      "  value 2  "   ]      ,  "key 3":      [      "  value 3  "   ]       }`,
			expectedSeen: map[string]string{`"key 1"`: `      [      "  value 1  "   ]      `, `"key 2"`: `      [      "  value 2  "   ]      `, `"key 3"`: `      [      "  value 3  "   ]       `},
		},
		{
			name:         "nested-objects",
			input:        `{"key 1" :      {      "nested key 1": "nested  value 1  "   }      ,  "key 2":      {      "nested key 2"  : "nested  value 2  "   }      ,  "key 3":      {      "nested key 3"  : "nested  value 3  "   }       }`,
			expectedSeen: map[string]string{`"key 1"`: `      {      "nested key 1": "nested  value 1  "   }      `, `"key 2"`: `      {      "nested key 2"  : "nested  value 2  "   }      `, `"key 3"`: `      {      "nested key 3"  : "nested  value 3  "   }       `},
		},
		{
			name:         "nested-last-object",
			input:        `{"key":{ "nested key "  : "nested  value   " }}`,
			expectedSeen: map[string]string{`"key"`: `{ "nested key "  : "nested  value   " }`},
		},
		{
			name:         "nested-last-object",
			input:        `{"key":      {      "nested key "  : "nested  value   "   }      }`,
			expectedSeen: map[string]string{`"key"`: `      {      "nested key "  : "nested  value   "   }      `},
		},
		{
			name:                     "null",
			input:                    "null",
			unexpectedScannerOpError: true,
		},
		{
			name:                     "array",
			input:                    `[{"k":"v"}]`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "number",
			input:                    `1`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "float",
			input:                    `1.234`,
			unexpectedScannerOpError: true,
		},
		{
			name:                     "string",
			input:                    `"1234"`,
			unexpectedScannerOpError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{"k":"v"`,
			expectedUnexpectedEndOfStringError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{"k":"v`,
			expectedUnexpectedEndOfStringError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{"k":`,
			expectedUnexpectedEndOfStringError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{"k"`,
			expectedUnexpectedEndOfStringError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{"k`,
			expectedUnexpectedEndOfStringError: true,
		},
		{
			name:                               "unterminated-json",
			input:                              `{`,
			expectedUnexpectedEndOfStringError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := &scanner{}
			scanner.reset()
			seen := map[string]string{}
			i, err := walkObject(scanner, tc.input, 0, func(keyFrom, keyTo, valueFrom, valueTo int) {
				key := tc.input[keyFrom:keyTo]
				value := tc.input[valueFrom:valueTo]
				assert.NotContains(t, seen, key)
				seen[key] = value
			})
			if tc.expectedSyntaxError {
				require.Equal(t, scanner.err, err)
			} else if tc.unexpectedScannerOpError {
				require.Equal(t, tc.unexpectedScannerOpError, err)
			} else if tc.expectedUnexpectedEndOfStringError {
				require.Equal(t, errUnexpectedEndOfString, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.input), i)
				require.Equal(t, tc.expectedSeen, seen)
			}
		})
	}
}
