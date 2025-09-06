package main

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ConnHandler struct {
	conn net.Conn

	queue chan []byte
	wg    sync.WaitGroup

	closeOnce sync.Once
	closed    chan struct{}
	onWrite   func(cw *ConnHandler, n int, err error)

	limiterMu    sync.RWMutex
	writeLimiter *rate.Limiter
	readLimiter  *rate.Limiter
}

// 新建 ConnHandler，可指定读写限速（bytes/s），0 或负数表示不限速
func NewConnHandler(conn net.Conn, queueSize int, writeBps, readBps int, onWrite func(cw *ConnHandler, n int, err error)) *ConnHandler {
	cw := &ConnHandler{
		conn:    conn,
		queue:   make(chan []byte, queueSize),
		closed:  make(chan struct{}),
		onWrite: onWrite,
	}

	if writeBps > 0 {
		cw.writeLimiter = rate.NewLimiter(rate.Limit(writeBps), writeBps)
	}
	if readBps > 0 {
		cw.readLimiter = rate.NewLimiter(rate.Limit(readBps), readBps)
	}

	cw.wg.Add(1)
	go cw.writer()
	return cw
}

func (cw *ConnHandler) writer() {
	defer cw.wg.Done()
	for {
		select {
		case data, ok := <-cw.queue:
			if !ok {
				return
			}

			// 写限速
			if cw.getWriteLimiter() != nil {
				_ = cw.getWriteLimiter().WaitN(context.Background(), len(data))
			}

			_ = cw.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			n, err := cw.conn.Write(data)
			cw.onWrite(cw, n, err)
			if err != nil {
				return
			}

		case <-cw.closed:
			return
		}
	}
}

// ----------------- 对外方法 -----------------

func (cw *ConnHandler) Write(data []byte) {
	cw.queue <- data
}

// Read 限速
func (cw *ConnHandler) Read(p []byte) (int, error) {
	n, err := cw.conn.Read(p)
	if err != nil {
		return n, err
	}

	// 消耗读令牌，阻塞直至可读
	if cw.getReadLimiter() != nil {
		_ = cw.getReadLimiter().WaitN(context.Background(), n)
	}
	return n, nil
}

func (cw *ConnHandler) Close() error {
	cw.closeOnce.Do(func() {
		close(cw.queue)
		close(cw.closed)
	})
	cw.wg.Wait()
	return cw.conn.Close()
}

// ----------------- 限速相关 -----------------

func (cw *ConnHandler) getWriteLimiter() *rate.Limiter {
	cw.limiterMu.RLock()
	defer cw.limiterMu.RUnlock()
	return cw.writeLimiter
}

func (cw *ConnHandler) getReadLimiter() *rate.Limiter {
	cw.limiterMu.RLock()
	defer cw.limiterMu.RUnlock()
	return cw.readLimiter
}

func (cw *ConnHandler) SetWriteLimit(bytesPerSec int) {
	cw.limiterMu.Lock()
	defer cw.limiterMu.Unlock()
	if bytesPerSec <= 0 {
		cw.writeLimiter = nil
	} else {
		cw.writeLimiter = rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec)
	}
}

func (cw *ConnHandler) SetReadLimit(bytesPerSec int) {
	cw.limiterMu.Lock()
	defer cw.limiterMu.Unlock()
	if bytesPerSec <= 0 {
		cw.readLimiter = nil
	} else {
		cw.readLimiter = rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec)
	}
}
