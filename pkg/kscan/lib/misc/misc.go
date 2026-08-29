package misc

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

func StrArr2IntArr(strArr []string) ([]int, error) {
	var intArr []int
	for _, value := range strArr {
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return nil, err
		}
		intArr = append(intArr, intValue)
	}
	return intArr, nil
}

func Str2Int(str string) int {
	intValue, err := strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return intValue
}

func IntArr2StrArr(intArr []int) []string {
	var strArr []string
	for _, value := range intArr {
		strValue := strconv.Itoa(value)
		strArr = append(strArr, strValue)
	}
	return strArr
}

func IsInStrArr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func IsInIntArr(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func ReadLine(fileName string, handler func(string, bool)) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		line = FixLine(line)
		handler(line, true)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func ReadLineAll(fileName string) []string {
	var strArr []string
	f, err := os.Open(fileName)
	if err != nil {
		return strArr
	}
	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		line = FixLine(line)
		strArr = append(strArr, line)
		if err != nil {
			if err == io.EOF {
				return strArr
			}
			return strArr
		}
	}
}

func FixLine(line string) string {
	line = strings.ReplaceAll(line, "\r", "")
	line = strings.ReplaceAll(line, "\t", "")
	line = strings.ReplaceAll(line, "\r", "")
	line = strings.ReplaceAll(line, "\n", "")
	line = strings.ReplaceAll(line, "\xc2\xa0", "")
	line = strings.ReplaceAll(line, " ", "")
	return line
}

func UniStrAppend(slice []string, elems ...string) []string {
	for _, elem := range elems {
		if IsInStrArr(slice, elem) {
			continue
		} else {
			slice = append(slice, elem)
		}
	}
	return slice
}

func FileIsExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func Xrange(args ...int) []int {
	var start, stop int
	var step = 1
	var r []int
	switch len(args) {
	case 1:
		stop = args[0]
		start = 0
	case 2:
		start, stop = args[0], args[1]
	case 3:
		start, stop, step = args[0], args[1], args[2]
	default:
		return nil
	}
	if start > stop {
		return nil
	}
	if step < 0 {
		return nil
	}

	for i := start; i <= stop; i += step {
		r = append(r, i)
	}
	return r
}

func FilterPrintStr(s string) string {
	// Convert the string to a rune array
	srcRunes := []rune(s)
	// Create a new rune array to store the filtered data
	dstRunes := make([]rune, 0, len(srcRunes))
	// Filter invisible characters; according to the table above, 0-32 and 127 are invisible characters
	for _, c := range srcRunes {
		if c >= 0 && c <= 31 {
			continue
		}
		if c == 127 {
			continue
		}
		if c > 65519 {
			continue
		}
		dstRunes = append(dstRunes, c)
	}
	return string(dstRunes)
}

func StrMap2Str(stringMap map[string]string, keyPrint bool) string {
	var rArr []string
	var assistArr []string
	for key, value := range stringMap {
		if value == "" {
			continue
		}
		if IsInStrArr(assistArr, value) == true {
			continue
		}
		assistArr = append(assistArr, value)
		if keyPrint == true {
			rArr = append(rArr, fmt.Sprintf("%s:%s", key, value))
		} else {
			rArr = append(rArr, value)
		}
	}
	return strings.Join(rArr, "、")
}

func MustLength(s string, i int) string {
	if len(s) > i {
		return s[:i]
	}
	return s
}

func Percent(int1 int, int2 int) string {
	float1 := float64(int1)
	float2 := float64(int2)
	f := 1 - float1/float2
	f = f * 100
	return strconv.FormatFloat(f, 'f', 2, 64)
}

func StrRandomCut(s string, length int) string {
	sRune := []rune(s)
	if len(sRune) > length {
		i := rand.Intn(len(sRune) - length)
		return string(sRune[i : i+length])
	} else {
		return s
	}
}

func RemoveDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok { //If the element is not found in the dictionary, ok=false, !ok is true, so append the element to the slice.
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func RemoveDuplicateElementForMultiple(mainArr, otherArr []string) []string {
	//Merge all secondary slices into one slice
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range otherArr {
		temp[item] = struct{}{}
	}
	for _, item := range mainArr {
		if _, ok := temp[item]; ok == false {
			result = append(result, item)
		}
	}
	return result
}

func WriteLine(fileName string, byte []byte) error {
	//file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	//On successful creation, suspend and close the file stream; execute before the function ends
	defer file.Close()
	//NewWriter creates a *Writer that writes to w with a buffer of default size for the target file.
	writer := bufio.NewWriter(file)
	//The writer writes the content to the buffer. Returns the number of bytes written.
	_, err = writer.Write(byte)
	//The Flush method flushes the buffered data to the underlying io.Writer interface. If missing, the data remains in the buffer and is not written to the io.Writer interface
	_ = writer.Flush()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return err
}

func Base64Encode(keyword string) string {
	input := []byte(keyword)
	encodeString := base64.StdEncoding.EncodeToString(input)
	return encodeString
}

func Base64Decode(encodeString string) (string, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(encodeString)
	return string(decodeBytes), err
}

func CloneStrMap(strMap map[string]string) map[string]string {
	newStrMap := make(map[string]string)
	for k, v := range strMap {
		newStrMap[k] = v
	}
	return newStrMap
}

func CloneIntMap(intMap map[int]string) map[int]string {
	newIntMap := make(map[int]string)
	for k, v := range intMap {
		newIntMap[k] = v
	}
	return newIntMap
}

func RandomString(i ...int) string {
	var length int
	var str string
	if len(i) != 1 {
		length = 32
	} else {
		length = i[0]
	}
	Char := "01234567890abcdef"
	for range Xrange(length) {
		j := rand.Intn(len(Char) - 1)
		str += Char[j : j+1]
	}
	return str
}

func Intersection(a []string, b []string) (inter []string) {
	for _, s1 := range a {
		for _, s2 := range b {
			if s1 == s2 {
				inter = append(inter, s1)
			}
		}
	}
	return inter
}

func First2Upper(s string) string {
	return strings.ToUpper(s[:1]) + s[1:]
}

func First2UpperForSlice(s []string) []string {
	var r []string
	for _, str := range s {
		r = append(r, First2Upper(str))
	}
	return r
}

func FixMap(m map[string]string) map[string]string {
	var arr []string
	rm := make(map[string]string)
	for key, value := range m {
		if value == "" {
			continue
		}
		if IsInStrArr(arr, value) {
			continue
		}
		arr = append(arr, value)
		rm[key] = value
	}
	return rm
}

func AutoWidth(s string, length int) int {
	length1 := len(s)
	length2 := len([]rune(s))

	if length1 == length2 {
		return length
	}
	return length - (length1-length2)/2
}
