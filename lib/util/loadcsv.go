package util

import (
	"encoding/csv"
	"os"
)

type CSVReader interface {
	ReadLine(line []string)
}

// Next step: load osvdb and drive the execution
func ReadCsv(filename string, data CSVReader) error {
	// Open CSV file
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read File into a Variable
	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return err
	}
	for _, line := range lines {
		data.ReadLine(line)
	}
	return nil
}
