package util

import (
	"sync"
	"time"
)

// Delayed auto-clear object
type delayClearObj struct {
	GetCacheObj func() interface{} // Return the cache object
	FnCbk       func()             // Callback function
	Time        int64              // The time when timing starts
	DelayCall   int64              // How many seconds to delay before calling FnCbk
}

// cache delay (sec)
//var nCacheTime = time.Second * 60

// Memory cleanup registration
var delayClear sync.Map

// Register delayed cleanup
//
//	n0 0 means execute after 60 seconds
func RegDelayCbk(szKey string, fnCbk func(), cache func() interface{}, n0 int64, DelayCall int64) {
	delayClear.Store(szKey, &delayClearObj{Time: time.Now().Unix() - n0, FnCbk: fnCbk, GetCacheObj: cache})
}

// Reset the time counter
func UpTime(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.Time = time.Now().Unix()
		delayClear.Store(szKey, x1)
	}
}

// Get the cache object
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

// Execute immediately
func DoNow(szKey string) {
	if o, ok := delayClear.Load(szKey); ok {
		x1 := o.(*delayClearObj)
		x1.FnCbk()
		delayClear.Delete(szKey)
	}
}

// Single instance running
var IsDo = make(chan struct{}, 1)

func DoSleep() {
	time.Sleep(4 * time.Second)
}

// Delayed cleanup
func DoDelayClear(Wg1 ...*sync.WaitGroup) {
	var wg2 *sync.WaitGroup
	if 0 < len(Wg1) && nil != Wg1[0] {
		wg2 = Wg1[0]
	} else {
		wg2 = Wg
	}
	IsDo <- struct{}{}
	wg2.Add(1)
	go func() {
		defer func() {
			<-IsDo
			wg2.Done()
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
