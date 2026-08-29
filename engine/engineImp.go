package engine

import (
	"context"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pocs_go"
	"github.com/panjf2000/ants/v2"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
)

// Engine object, global singleton
type Engine struct {
	Context      *context.Context       // Context
	Wg           *sync.WaitGroup        // Wg
	Pool         int                    // Thread pool
	PoolFunc     *ants.PoolWithFunc     // Thread invocation
	EventData    chan *models.EventData // Data queue
	caseScanFunc sync.Map
}

var G_Engine *Engine

// Create engine
//
//	By default, each goroutine occupies 8KB of memory
//	A machine with 8GB of memory can only create 8GB/8KB = 1000000 goroutines at best
//	Moreover, the system needs to reserve some memory for daily management tasks, and the go runtime needs memory for gc and goroutine switching, etc.
func NewEngine(c *context.Context, pool int) *Engine {
	if nil != util.G_Engine {
		return util.G_Engine.(*Engine)
	}
	x1 := &Engine{Context: c, Wg: &sync.WaitGroup{}, Pool: pool, EventData: make(chan *models.EventData, pool)}
	p, err := ants.NewPoolWithFunc(pool, func(i interface{}) {
		defer x1.Wg.Done()
		x1.DoEvent(i.(*models.EventData))
	})
	if nil != err {
		log.Println("ants.NewPoolWithFunc is error: ", err)
	}
	x1.PoolFunc = p
	util.G_Engine = x1
	G_Engine = x1
	util.EngineFuncFactory = x1.EngineFuncFactory
	util.SendEvent = x1.SendEvent
	log.Println("Engine init ok")
	return x1
}

func (e *Engine) EngineFuncFactory(nT int64, fnCbk interface{}) {
	e.RegCaseScanFunc(nT, fnCbk)
}

func (e *Engine) RegCaseScanFunc(nType int64, fnCbk interface{}) {
	e.caseScanFunc.Store(nType, fnCbk)
}

func (r *Engine) GetCaseScanFunc() *sync.Map {
	return &r.caseScanFunc
}

// Release resources
func (e *Engine) Close() {
	defer ants.Release()
	e.PoolFunc.Release()
	e.Wg.Wait()
}

// Function used by case scanning
func (e *Engine) DoCase(ed *models.EventData) util.EngineFuncType {
	if i, ok := e.caseScanFunc.Load(ed.EventType); ok {
		return i.(util.EngineFuncType)
	}
	return nil
}

// Send a set of related events
func (e *Engine) SendEvent(evt *models.EventData, argsTypes ...int64) {
	for _, i := range argsTypes {
		var n1 = models.EventData{}
		util.DeepCopy(evt, &n1)
		n1.EventType = i
		e.EventData <- &n1
	}
}

// Execute event code, for internal use
//
//	Each event handles deduplication on its own
//	Each event executes asynchronously
//	Each event type can independently control the concurrency count
func (e *Engine) DoEvent(ed *models.EventData) {
	if nil != ed && nil != ed.EventData && 0 < len(ed.EventData) {
		fnCall := e.DoCase(ed)
		if nil != fnCall {
			fnCall(ed, ed.EventData...)
		} else {
			log.Printf("can not find fnCall case func %v\n", ed)
		}
	}
}

func (x1 *Engine) Running() {
	// Asynchronously start a thread to handle the detection, to avoid
	go func() {
		defer func() {
			x1.Close()
		}()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		tK := time.NewTicker(2 * time.Second)
		defer tK.Stop()
		//nMax := 120 // exit if no messages come in for xxx seconds
		//nCnt := 0
		for {
			select {
			case <-util.Ctx_global.Done():
				close(util.PocCheck_pipe)
				return
			case <-c:
				util.DoCbk("exit")
				os.Exit(1)
			case x2 := <-x1.EventData: // Control of various scans
				if nil != x2 && nil != x2.EventData {
					x1.Wg.Add(1)
					x1.PoolFunc.Invoke(x2)
				}
			case x1, ok := <-util.PocCheck_pipe:
				if util.GetValAsBool("NoPOC") || nil == x1 || !ok {
					//close(util.PocCheck_pipe) // This line will error when the NoPOC flag is enabled, since other processes cannot pass through
					log.Println("go_poc_checkout is over")
					continue
				}
				//nCnt = 0
				if !util.TestRepeat(x1, *x1.Wappalyzertechnologies, x1.URL) {
					log.Printf("<-util.PocCheck_pipe: %+v  %s", *x1.Wappalyzertechnologies, x1.URL)
					func(x99 *util.PocCheck) {
						util.DoSyncFunc(func() {
							pocs_go.POCcheck(*x99.Wappalyzertechnologies, x99.URL, x99.FinalURL, x99.Checklog4j)
						})
					}(x1)
				}
			case <-tK.C:
				util.DoDelayClear(x1.Wg) // panic: sync: WaitGroup misuse: Add called concurrently with Wait
			}
		}
	}()
}

// Main entry point of the engine
func init() {
	//log.Println("engineImp.go run")
	lib.GConfigServer.OnClient = true
	util.RegInitFunc4Hd(func() {
		// The following variables cannot be moved into DoSyncFunc, otherwise the global variables will affect the subsequent init, resulting in invalid memory
		NewEngine(&util.Ctx_global, util.GetValAsInt("ScanPoolSize", 5000))

		util.DoSyncFunc(func() {
			util.G_Engine.(*Engine).Running()
		})
	})
}
