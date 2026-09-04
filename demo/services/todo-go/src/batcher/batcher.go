package batcher

import (
	"fmt"
	"log"
	"time"

	"github.com/rqlite/gorqlite"
)

type writeRequest struct {
	stmt     gorqlite.ParameterizedStatement
	response chan writeResponse
}

type writeResponse struct {
	result gorqlite.WriteResult
	err    error
}

type Batcher struct {
	conn     *gorqlite.Connection
	reqCh    chan writeRequest
	maxBatch int
	window   time.Duration
	stopCh   chan struct{}
	done     chan struct{}
}

func New(dsn string, maxBatch int, windowMs int) (*Batcher, error) {
	conn, err := gorqlite.Open(dsn)
	if err != nil {
		return nil, fmt.Errorf("batcher: failed to open gorqlite connection: %w", err)
	}

	conn.SetExecutionWithTransaction(false)

	return &Batcher{
		conn:     conn,
		reqCh:    make(chan writeRequest, 4096),
		maxBatch: maxBatch,
		window:   time.Duration(windowMs) * time.Millisecond,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

func (b *Batcher) Start() {
	go b.loop()
	log.Printf("batcher: started (maxBatch=%d, window=%v)", b.maxBatch, b.window)
}

func (b *Batcher) Stop() {
	close(b.stopCh)
	<-b.done
	b.conn.Close()
	log.Println("batcher: stopped")
}

func (b *Batcher) Submit(query string, args ...interface{}) error {
	req := writeRequest{
		stmt: gorqlite.ParameterizedStatement{
			Query:     query,
			Arguments: args,
		},
		response: make(chan writeResponse, 1),
	}
	select {
	case b.reqCh <- req:
	case <-b.stopCh:
		return fmt.Errorf("batcher: shutting down")
	}
	resp := <-req.response
	return resp.err
}

func (b *Batcher) loop() {
	defer close(b.done)
	for {

		var first writeRequest
		select {
		case first = <-b.reqCh:
		case <-b.stopCh:
			b.drain()
			return
		}

		batch := []writeRequest{first}
		timer := time.NewTimer(b.window)

	collect:
		for len(batch) < b.maxBatch {
			select {
			case req := <-b.reqCh:
				batch = append(batch, req)
			case <-timer.C:
				break collect
			case <-b.stopCh:
				timer.Stop()
				b.flush(batch)
				b.drain()
				return
			}
		}
		timer.Stop()

		b.flush(batch)
	}
}

func (b *Batcher) flush(batch []writeRequest) {
	if len(batch) == 0 {
		return
	}

	stmts := make([]gorqlite.ParameterizedStatement, len(batch))
	for i, req := range batch {
		stmts[i] = req.stmt
	}

	results, err := b.conn.WriteParameterized(stmts)

	if err != nil {

		for _, req := range batch {
			req.response <- writeResponse{err: err}
		}
		return
	}

	for i, req := range batch {
		if i < len(results) {
			req.response <- writeResponse{
				result: results[i],
				err:    results[i].Err,
			}
		} else {
			req.response <- writeResponse{
				err: fmt.Errorf("batcher: missing result for statement %d", i),
			}
		}
	}
}

func (b *Batcher) drain() {
	for {
		select {
		case req := <-b.reqCh:
			b.flush([]writeRequest{req})
		default:
			return
		}
	}
}
