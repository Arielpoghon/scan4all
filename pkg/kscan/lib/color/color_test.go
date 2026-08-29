package color

import (
	"fmt"
	"testing"
)

type gogo struct {
	string
	int
}

func TestColor(t *testing.T) {

	fmt.Println(Red("Red color test!!! "))
	fmt.Println("Normal test!!! ")
	fmt.Println(Bold("Bold test!!! "))
	fmt.Println(Bold(Red("Bold red color test!!! ")))
	fmt.Printf("\x1b[%dmhello world 30: Black \x1b[0m\n", 30)
	fmt.Printf("\x1b[%dmhello world 31: Red \x1b[0m\n", 31)
	fmt.Printf("\x1b[%dmhello world 32: Green \x1b[0m\n", 32)
	fmt.Printf("\x1b[%dmhello world 33: Yellow \x1b[0m\n", 33)
	fmt.Printf("\x1b[%dmhello world 34: Blue \x1b[0m\n", 34)
	fmt.Printf("\x1b[%dmhello world 35: Purple \x1b[0m\n", 35)
	fmt.Printf("\x1b[%dmhello world 36: Dark Green \x1b[0m\n", 36)
	fmt.Printf("\x1b[%dmhello world 37: White \x1b[0m\n", 37)

	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 47: White 30: Black \n", 47, 30)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 46: Dark Green 31: Red \n", 46, 31)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 45: Purple 32: Green \n", 45, 32)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 44: Blue 33: Yellow \n", 44, 33)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 43: Yellow 34: Blue \n", 43, 34)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 42: Green 35: Purple \n", 42, 35)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 41: Red 36: Dark Green \n", 41, 36)
	fmt.Printf("\x1b[%d;%dmhello world \x1b[0m 40: Black 37: White \n", 40, 37)
}

func TestStr(t *testing.T) {
	a := gogo{
		"gogo",
		1234,
	}
	fmt.Print(a)
}
