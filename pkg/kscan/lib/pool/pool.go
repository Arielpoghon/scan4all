package pool

import (
	"errors"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/misc"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/smap"
	"io"
	"log"
	"sync"
	"time"
)

var logger = Logger(log.New(io.Discard, "", log.Ldate|log.Ltime))

type Logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

// Create a worker; each worker is abstracted as a function that can execute tasks
type Worker struct {
	f func(interface{}) (interface{}, error)
}

// Create a worker through NewWorker
func NewWorker(f func(interface{}) interface{}) *Worker {
	return &Worker{
		f: func(in interface{}) (out interface{}, err error) {
			defer func() {
				if e := recover(); e != nil {
					err = errors.New(fmt.Sprint("param: ", in, e))
					logger.Println(err)
				}
			}()
			out = f(in)
			return out, err
		},
	}
}

var enableDevDebug bool

func init() {
	util.RegInitFunc(func() {
		enableDevDebug = util.GetValAsBool("enableDevDebug")
	})
}

// Execute worker
func (t *Worker) Run(in interface{}) (interface{}, error) {
	return t.f(in)
}

// Pool
type Pool struct {
	//Template function
	Function func(interface{}) interface{}
	//Pool input queue
	In chan interface{}
	//Pool output queues
	Out chan interface{}
	//size is used to indicate the pool size; it cannot exceed this limit.
	threads int
	//Coroutine startup wait time
	Interval time.Duration
	//The list of tasks being executed
	JobsList *smap.SMap
	//jobs represents the channel for executing tasks, used as a queue. We take tasks out of the slice, store them in the channel, then take tasks out of the channel and execute them.
	Jobs chan *Worker
	//Used for blocking
	wg *sync.WaitGroup
	//Early termination flag
	Done bool
}

// Instantiate the worker pool
func NewPool(threads int) *Pool {
	return &Pool{
		threads:  threads,
		JobsList: smap.New(),
		wg:       &sync.WaitGroup{},
		Out:      make(chan interface{}),
		In:       make(chan interface{}),
		Function: nil,
		Done:     false,
		Interval: time.Duration(0),
	}
}

// Take a task out of jobs and execute it.
func (p *Pool) work() {
	//Decrease the value of the waitGroup counter
	defer func() {
		p.wg.Done()
	}()
	for param := range p.In {
		if p.Done {
			return
		}
		//Get the unique ticket of the task
		Tick := p.NewTick()
		//Push the work task into the work list
		p.JobsList.Set(Tick, param)
		//Set the work content
		f := NewWorker(p.Function)
		//Start working, output the work result
		//if enableDevDebug {
		fmt.Printf(" hydra: %v\r", param)
		//}
		out, err := f.Run(param)
		//Output the work result
		p.Out <- out
		//Work is done, delete it from the work list
		p.JobsList.Delete(Tick)
		if err != nil {
			logger.Println(err)
		}
	}
}

// Execute the tasks in the worker pool
func (p *Pool) Run() {
	//Only start a limited number of coroutines; the number must not exceed the pool-set limit to prevent resource exhaustion
	for i := 0; i < p.threads; i++ {
		p.wg.Add(1)
		time.Sleep(p.Interval)
		go p.work()
	}
	p.Wait()
}

func (p *Pool) RunBack() {
	//Only start a limited number of coroutines; the number must not exceed the pool-set limit to prevent resource exhaustion
	for i := 0; i < p.threads; i++ {
		p.wg.Add(1)
		time.Sleep(p.Interval)
		go p.work()
	}
}

func (p *Pool) Wait() {
	p.wg.Wait()
	//Close the output channel
	p.OutDone()
}

// End the input channel
func (p *Pool) InDone() {
	close(p.In)
}

// End the output channel
func (p *Pool) OutDone() {
	close(p.Out)
}

// Send an early termination command to each work coroutine
func (p *Pool) Stop() {
	p.Done = true
}

// Generate a work ticket
func (p *Pool) NewTick() string {
	return misc.RandomString()
}

// Get the thread count
func (p *Pool) Threads() int {
	return p.threads
}

func SetLogger(log Logger) {
	logger = log
}
