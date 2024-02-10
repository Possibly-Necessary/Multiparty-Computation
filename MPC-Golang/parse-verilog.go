package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

// ___________________________________________ Verilog Parser Function_____________________________
func parseVerilog(filename string) (map[string]interface{}, []string, []string, error) {
	circuit := make(map[string]interface{}) // Map from wire name -> operation
	var inputs, outputs []string

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, nil, err
	}

	filecontents := string(data)
	lines := strings.Split(filecontents, ";")

	commentRegex := regexp.MustCompile(`(/\*.*?\*/)|(//.*$)`)
	for _, l := range lines {
		if l == "" {
			continue
		}
		l = commentRegex.ReplaceAllString(l, "") // Remove comments
		l = strings.TrimSpace(l)
		tokens := strings.Fields(l)
		if len(tokens) == 0 || tokens[0] == "module" || tokens[0] == "endmodule" {
			continue
		}
		tokens[len(tokens)-1] = strings.TrimRight(tokens[len(tokens)-1], ";")

		// Declaration
		if tokens[0] == "wire" || tokens[0] == "output" || tokens[0] == "input" {
			if len(tokens) != 2 {
				return nil, nil, nil, fmt.Errorf("unsupported statement: %s", l)
			}
			typ, name := tokens[0], tokens[1]
			if typ == "input" {
				inputs = append(inputs, name)
			} else if typ == "output" {
				outputs = append(outputs, name)
			}
			circuit[name] = nil
		} else if tokens[0] == "assign" { // Assignment
			if tokens[2] != "=" {
				return nil, nil, nil, fmt.Errorf("unsupported statement: %s", l)
			}
			lhs := tokens[1]
			if strings.Contains(lhs, "[") || strings.Contains(lhs, ":") {
				return nil, nil, nil, fmt.Errorf("unsupported statement: %s", l)
			}
			// This is a simplified version; you should expand it based on the operations you need to support
			rhs := strings.Join(tokens[3:], "")
			// Further processing of rhs to handle operations...
			circuit[lhs] = rhs // Placeholder for actual operation parsing
		} else {
			return nil, nil, nil, fmt.Errorf("unsupported statement: %s", l)
		}
	}

	return circuit, inputs, outputs, nil
}
