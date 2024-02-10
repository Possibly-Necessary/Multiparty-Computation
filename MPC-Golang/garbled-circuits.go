package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3" // For Keccak
)

var wg sync.WaitGroup

// Function to generates all combinations of 0s and 1s for n bits.
func product(n int) [][]int {
	total := 1 << n
	result := make([][]int, total)
	for i := range result {
		result[i] = make([]int, n)
		for j := range result[i] {
			result[i][j] = (i >> j) & 1
		}
	}
	return result
}

// labelTruthTable labels the truth table for a given gate and its inputs.
func labelTruthTable(outputName string, gate string, inputNames []string, labels map[string][]*big.Int, k int) ([][]*big.Int, error) {
	var logicTable [][]int
	switch gate {
	case "and":
		logicTable = [][]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}}
	case "or":
		logicTable = [][]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}}
	case "nand":
		logicTable = [][]int{{1, 1}, {1, 1}, {1, 0}, {0, 1}}
	case "xnor":
		logicTable = [][]int{{1, 1}, {0, 1}, {1, 0}, {0, 0}}
	case "xor":
		logicTable = [][]int{{0, 0}, {1, 1}, {1, 0}, {0, 1}}
	case "ornot":
		logicTable = [][]int{{1, 0}, {1, 1}, {0, 0}, {1, 1}}
	case "nor":
		logicTable = [][]int{{1, 0}, {0, 0}, {0, 0}, {0, 1}}
	case "andnot":
		logicTable = [][]int{{0, 0}, {1, 0}, {1, 0}, {1, 1}}
	case "not":
		logicTable = [][]int{{1}, {0}}
	case "const_0":
		logicTable = [][]int{{0}}
	case "const_1":
		logicTable = [][]int{{1}}
	default:
		return nil, fmt.Errorf("unsupported gate %s", gate)
	}

	maxValue := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil) // 2^k as the upper bound for the label value
	minValue := big.NewInt(1)                                              // Minimum value for label
	// labels for each variable
	for _, varName := range append([]string{outputName}, inputNames...) {
		if _, exists := labels[varName]; !exists {
			// maxValue - 1; randBigIntRange() is inclusive and we want [minValue, 2^k - 1]
			label0 := randBigIntRange(minValue, new(big.Int).Sub(maxValue, big.NewInt(1))) // Generate label for 0
			label1 := randBigIntRange(minValue, new(big.Int).Sub(maxValue, big.NewInt(1))) // Generate label for 1
			labels[varName] = []*big.Int{label0, label1}                                   // Assign the 0 and 1 labels for each var
		}
	}

	var labeledTable [][]*big.Int
	for _, inpValues := range product(len(inputNames)) {
		var outputValue int
		if gate == "not" { // Special case for NOT gate
			outputValue = logicTable[inpValues[0]][0]
		} else if gate == "const_0" || gate == "const_1" { // Special case for constant gates
			outputValue = logicTable[0][0]
		} else {
			outputValue = logicTable[inpValues[0]*2+inpValues[1]][0] // Adjust according to the logic table structure
		}
		outputLabel := labels[outputName][outputValue]
		inputLabels := make([]*big.Int, len(inputNames))
		for i, inputName := range inputNames {
			inputLabels[i] = labels[inputName][inpValues[i]]
		}
		labeledTable = append(labeledTable, append([]*big.Int{outputLabel}, inputLabels...))
	}

	return labeledTable, nil
}

// _____________________________________ More Table Stuff ____________________________________
// Function that combines two lables into a single key using Keccak
func combineKeys(keys [][]byte) []byte { // removed []uint64, k int from input

	h := sha3.New256() //Initialize a new SHA3-256 hash
	for _, ki := range keys {
		h.Write(ki) // Update the hash with the key
	}
	return h.Sum(nil) // Compute and return the hash
}

// Function that garbels the table
func garbleTable(labeledTable [][]*big.Int, k int) ([][]byte, error) {
	rand.Seed(time.Now().Unix())
	result := make([][]byte, len(labeledTable))

	for i, row := range labeledTable {
		outputLabel := row[0]
		inputLabels := row[1:]

		inputLabelsBytes := make([][]byte, len(inputLabels))

		for j, label := range inputLabels {
			labelBytes := label.Bytes() // Convert *big.Int to []byte
			inputLabelsBytes[j] = labelBytes
		}

		// Combine input labels into a single key
		key := combineKeys(inputLabelsBytes)

		// Encrypt the output label with the combined key
		ciphertext, nonce, err := symmetricEnc(key, outputLabel)
		if err != nil {
			fmt.Println("Error encrypting label:", err)
			return nil, err
		}
		// Combine ciphertext and nonce for storing in result
		garbledEntry := append(ciphertext, nonce...)
		result[i] = garbledEntry
	}
	// Shuffle the result
	rand.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})
	return result, nil
}

// Function that 'topologically' sort on the circuit represented as a dependency graph
func topoOrder(circuit map[string][]string, inputs []string, outputs []string) []string {
	var postOrder []string
	visited := make(map[string]bool)

	var visit func(wireName string)
	visit = func(wireName string) {
		if visited[wireName] {
			return
		}
		visited[wireName] = true
		if _, found := find(inputs, wireName); !found {
			inputWireNames := circuit[wireName][1:] // Skipping the gate type
			for _, inputWire := range inputWireNames {
				visit(inputWire)
			}
		}
		postOrder = append(postOrder, wireName)
	}

	for _, outputWire := range outputs {
		visit(outputWire)
	}

	return postOrder
}

// Helper function to check if an item is in a slice.
func find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// Function that garbles the circuit
func garbleCircuit(circuit map[string][]string, inputs, outputs []string, k int) ([][]interface{}, map[string][]*big.Int, map[string]int) {
	labels := make(map[string][]*big.Int)
	var garbledTables [][]interface{}

	// Topologically order all the wires
	wires := topoOrder(circuit, inputs, outputs)

	// Create a wire index map based on the topological order
	wireIndex := make(map[string]int)
	for i, wire := range wires {
		wireIndex[wire] = i
	}

	for _, wireName := range wires {
		if _, found := find(inputs, wireName); found {
			fmt.Println("input wire:", wireName)
			garbledTables = append(garbledTables, []interface{}{nil, nil}) // Input wire
			continue
		}

		gate := circuit[wireName][0]            // The gate type
		inputWireNames := circuit[wireName][1:] // The input wires for this gate
		fmt.Println(wireName, gate, inputWireNames)

		labeledTable, err := labelTruthTable(wireName, gate, inputWireNames, labels, k)
		if err != nil {
			fmt.Println("Error labeling truth table:", err)
			continue
		}

		garbledTable, err := garbleTable(labeledTable, k)
		if err != nil {
			panic("Error garbling table")
		}

		// Get input wire indexes
		var inputWireIndexes []int
		for _, inputWire := range inputWireNames {
			inputWireIndexes = append(inputWireIndexes, wireIndex[inputWire])
		}

		// Ensure all input wire indexes are valid
		for _, i := range inputWireIndexes {
			if i >= len(garbledTables) {
				fmt.Println("Assertion failed: input wire index out of range")
				return nil, nil, nil
			}
		}

		garbledTables = append(garbledTables, []interface{}{garbledTable, inputWireIndexes})
	}

	if len(garbledTables) != len(wires) {
		fmt.Println("Assertion failed: garbled tables length does not match wires length")
	}
	return garbledTables, labels, wireIndex
}

// Function that evaluates the garbled circuit
func evalGarbledCircuit(garbledTables [][]interface{}, circuitInputLabels map[int]*big.Int, outputWireIndexes []int) ([]*big.Int, error) {
	var evaluatedGates = make([]*big.Int, len(garbledTables))

	for i, table := range garbledTables {
		garbledTable, inputWireIndexes := table[0].([][]byte), table[1].([]int)

		if label, exists := circuitInputLabels[i]; exists { // This is an input wire
			evaluatedGates[i] = label
			continue
		}

		var outputLabel *big.Int
		found := false

		for _, row := range garbledTable {
			ciphertext, nonce := row[:len(row)-12], row[len(row)-12:]

			var gateInputLabels [][]byte
			for _, index := range inputWireIndexes {
				gateInputLabels = append(gateInputLabels, evaluatedGates[index].Bytes())
			}

			key := combineKeys(gateInputLabels)
			label, err := symmetricDec(key, ciphertext, nonce)
			if err == nil { // If decryption is successful, we found our label
				outputLabel = label
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("unable to decrypt garbled table for gate %d", i)
		}
		evaluatedGates[i] = outputLabel
		fmt.Println("evaluated gate", i, "=", outputLabel)
	}
	if len(evaluatedGates) != len(garbledTables) {
		return nil, fmt.Errorf("assertion failed: evaluated gates length does not match garbled tables length")
	}

	var outputLabels []*big.Int
	for _, index := range outputWireIndexes {
		outputLabels = append(outputLabels, evaluatedGates[index])
	}
	return outputLabels, nil
}

//__________________________________________ Arthur-Merlin Garble Table Set UP ________________________________

func wireValues(prefix string, X *big.Int, bits int) map[string]*big.Int {
	// Example implementation; adjust according to your requirements
	values := make(map[string]*big.Int)
	for i := 0; i < bits; i++ {
		bit := new(big.Int).And(new(big.Int).Rsh(X, uint(i)), big.NewInt(1))
		values[fmt.Sprintf("%s_%d", prefix, i)] = bit
	}
	return values
}

// MerlinSetupGarbledCircuit setups the garbled circuit for Merlin's input wires and performs oblivious transfers for Arthur's inputs.
func MerlinGarbledCircuit(circuit map[string][]string, inputWires, outputWires []string, X *big.Int, xBits, yBits, n, k int, ArthurChann, MerlinChann chan *big.Int, wg *sync.WaitGroup) {
	garbledTables, labels, wireIndex := garbleCircuit(circuit, inputWires, outputWires, k)

	var outputIndexes []int
	for _, wire := range outputWires {
		if index, exists := wireIndex[wire]; exists {
			outputIndexes = append(outputIndexes, index)
		}
	}
	// Convert labels to a format mapping from label to "wire_name=value"
	labelsToNames := make(map[*big.Int]string)
	for wire, v01 := range labels {
		for i, v := range v01 {
			labelsToNames[v] = fmt.Sprintf("%s=%d", wire, i)
		}
	}
	// Debug print
	for k, v := range labelsToNames {
		fmt.Println(k, "\t", v)
	}

	// Setup Merlin's input wires
	MerlinInputValues := wireValues("x", X, xBits)
	fmt.Println("Merlin input values:", MerlinInputValues)

	// Map of wireIndex -> given label (for Merlin's wires)
	MerlinInputLabels := make(map[int]*big.Int)
	for _, wire := range inputWires {
		if strings.HasPrefix(wire, "x_") {
			if value, ok := MerlinInputValues[wire]; ok { // Check if wire is in MerlinInputValues
				if index, ok := wireIndex[wire]; ok { // Chcek if wire has an index in wireInput
					MerlinInputLabels[index] = labels[wire][int(value.Int64())]
				}
			}
		}
	}

	// Wire inputs for Arthur ----------- this part needs revisiting
	ArthurInputIndexes := make([]int, yBits)
	for i := 0; i < yBits; i++ {
		ArthurInputIndexes[i] = wireIndex[fmt.Sprintf("y_%d", i)]
	}
	// Setup the oblivious transfer for Arthur's input wires
	e, d, N := txtBookRSA(n)
	wg.Add(yBits)
	for i := 0; i < yBits; i++ {
		m0, m1 := labels[fmt.Sprintf("y_%d", i)]
		go ObliviousTransferMerlin(m0, m1, e, d, N, ArthurChann, MerlinChann, wg)
	}
	wg.Wait()

	// In progress...

}

func ArthurGarbledCircuit(Y *big.Int, yBits, n, k int, wg *sync.WaitGroup) {

	// In progress...

}
