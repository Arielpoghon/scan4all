package go_utils

import (
	"log"
	"runtime"
	"strings"
)

type RegFuncs struct {
	FuncList []func()
}

// RegFunc registers a function.
func (r *RegFuncs) RegFunc(fn func()) {
	r.FuncList = append(r.FuncList, fn)
}

// Tick-related registry.
var TickFunc = new(RegFuncs)
var ReleaseFunc = new(RegFuncs)

// DoFunc invokes registered functions serially.
func (r *RegFuncs) DoFunc() {
	for _, c := range r.FuncList {
		c()
	}
}

// Catch Panic
//
//	in your func: defer CatchPanic()
func CatchPanic() {
	if o := recover(); nil != o {
		log.Println(o)
	}
}

// PrintCaller prints the full call chain up to this method.
func PrintCaller() {
	var i = 0
	for {
		i++
		if pc, file, line, ok := runtime.Caller(i); ok {
			fc := runtime.FuncForPC(pc)
			log.Printf("<-%s %s file:%s (line:%d)\n", strings.Repeat(":", i-1), fc.Name(), file, line) // , runtime.CallersFrames([]uintptr{pc})
			if "main.main" == fc.Name() {
				break
			}
		} else {
			break
		}
	}
}
