package lib

// Check whether scanType includes the checkType scan
func HasScanType(scanType int64, checkType int64) bool {
	return scanType&checkType == checkType
}

// Check whether scanType includes the checkType scan
func HasScanTypes(scanType int64, checkType ...int64) bool {
	return HasScanType(scanType, MergeScanType(checkType...))
}

// Merge all scan types
func MergeScanType(args ...int64) int64 {
	var i int64 = 0
	for _, j := range args {
		i = i | j
	}

	return i
}
