package go_utils

import (
	"sync"
	"time"
)

// delayClearObj supports delayed automatic cleanup.
type delayClearObj struct {
	GetCacheObj func() interface{} // Returns the cached object.
	FnCbk       func()             // Callback function.
	Time        int64              // Time when the initial period began.
	DelayCall   int64              // Delay in seconds before calling FnCbk.
}

// Cache delay in sec.
//var nCacheTime = time.Second * 60

// Registry for in-memory cleanup.
var delayClear sync.Map

// Registers a delayed cleanup.
//
//	n0; 0 means execute after 60 seconds.
func RegDelayCbk(szKey string, fnCbk func(), cache func() interface{}, n0 int64, DelayCall int64) {
	delayClear.Store(szKey, &delayClearObj{Time: time.Now().Unix() - n0, FnCbk: fnCbk, GetCacheObj: cache, DelayCall: DelayCall})
}

// UpTime resets the timer.
func UpTime(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.Time = time.Now().Unix()
		delayClear.Store(szKey, x1)
	}
}

// GetCache returns the cached object.
func GetCache(szKey string, bUpTime bool) interface{} {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		if bUpTime {
			UpTime(szKey)
		}
		return x1.GetCacheObj()
	}
	return nil
}

// DoNow executes the callback immediately.
func DoNow(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.FnCbk()
		delayClear.Delete(szKey)
	}
}

// Single-instance execution.
var IsDo = make(chan struct{}, 1)

func DoSleep() {
	time.Sleep(4 * time.Second)
}

// DoDelayClear performs delayed cleanup.
func DoDelayClear() {
	IsDo <- struct{}{}
	Wg.Add(1)
	go func() {
		defer func() {
			<-IsDo
			Wg.Done()
		}()
		nN := time.Now().Unix()
		delayClear.Range(func(key, value any) bool {
			if nil == value {
				delayClear.Delete(key)
				return true
			}
			x1 := value.(*delayClearObj)
			n09 := nN - x1.Time
			//log.Printf("n09 = %d, now = %d, x1.Time = %d", n09, nN, x1.Time)
			if n09 >= x1.DelayCall {
				x1.FnCbk()
				delayClear.Delete(key)
				//log.Println("nuclei is closed : ", key)
			}
			return true
		})
	}()
	return
}
