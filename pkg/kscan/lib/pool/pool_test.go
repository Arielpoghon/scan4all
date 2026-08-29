package pool

import (
	"testing"
)

func TestName(t *testing.T) {
	//NewTask is the function run in the worker pool. It needs to be instantiated before use.
	//w := NewWorker()
	//Instantiate the worker pool

	////Here enable another goroutine to write into the worker, otherwise it will appear "all goroutines are asleep"; you need to obtain a data from the pipeline, and this data must be put into the pipeline by another goroutine
	//go func() {
	//	for i := 1; i < 100; i++ {
	//		p.Jobs <- w //Put the functions that need to run into the worker pool sequentially.
	//	}
	//	close(p.Jobs)
	//}()
	//p.Run()

}
