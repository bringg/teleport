package utils

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchReadChanneWaitsForFirstMessage(t *testing.T) {
	// ctx is a context that will cancel at the end of the test. Any spawned
	// goroutines must exit when this context expires
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// GIVEN a buffered channel
	ch := make(chan int, 10)
	t.Cleanup(func() { close(ch) })

	// GIVEN a consumer process that reads a single batch of messages from the
	// channel
	var msgCount atomic.Int32
	go func() {
		for _, ok := range BatchReadChannel(ctx, ch, math.MaxInt32) {
			if !ok {
				return
			}
			msgCount.Add(1)
		}
	}()

	// WHEN I write a message to the channel after an arbitrary delay
	go func() {
		select {
		case <-ctx.Done():
			return

		case <-time.After(500 * time.Millisecond):
			ch <- 1
		}
	}()

	// EXPECT that the message was received in the single batch that was read
	require.EventuallyWithT(t,
		func(c *assert.CollectT) {
			assert.Equal(c, int32(1), msgCount.Load())
		},
		1*time.Second,
		10*time.Millisecond)
}

func TestReadBatchHonorsSizeLimit(t *testing.T) {
	const (
		msgCount  = 100
		batchSize = 11
	)

	// GIVEN a large buffered channel full of messages
	ch := make(chan int, msgCount)
	t.Cleanup(func() { close(ch) })
	for i := range msgCount {
		ch <- i
	}

	// WHEN I attempt to read a batch of messages, where the maximum batch size
	// is less than the number of pending items in the channel
	count := 0
	for _, ok := range BatchReadChannel(context.Background(), ch, batchSize) {
		require.True(t, ok)
		count++
	}

	require.Equal(t, batchSize, count)
}

func TestBatchReadChannelDetectsClose(t *testing.T) {
	const channelCapacity = 5

	type producer struct {
		ctx     context.Context
		cancel  context.CancelFunc
		ch      chan int
		closeCh bool
	}

	testCases := []struct {
		name      string
		msgCount  int
		closer    func(*producer)
		tolerance int
	}{
		{
			name: "empty channel",
			closer: func(p *producer) {
				p.closeCh = false
				close(p.ch)
			},
		},
		{
			name:     "non-empty channel",
			msgCount: 101,
			closer: func(p *producer) {
				p.closeCh = false
				close(p.ch)
			},
		},
		{
			name: "context with empty channel",
			closer: func(p *producer) {
				p.cancel()
			},
		},
		{
			name:     "context with non-empty channel",
			msgCount: 101,
			closer: func(p *producer) {
				p.cancel()
			},
			tolerance: channelCapacity,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// ctx is a context that will cancel at the end of the test. Any spawned
			// goroutines must exit when this context expires
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			// GIVEN an asynchronous producer process that writes messages into
			// a channel and then does something to indicate that there will be
			// no more messages...
			p := producer{
				ch:      make(chan int, channelCapacity),
				closeCh: true,
			}
			p.ctx, p.cancel = context.WithCancel(context.Background())
			t.Cleanup(func() {
				p.cancel()
				if p.closeCh {
					close(p.ch)
				}
			})
			go func() {
				for i := range test.msgCount {
					select {
					case p.ch <- i:
						continue
					case <-ctx.Done():
						return
					}
				}
				test.closer(&p)
			}()

			// WHEN I run a n asynchronous consumer process that logs all the
			// messages until it receives a close signal via a non-OK read
			var msgCount atomic.Int32
			var closeDetected atomic.Bool
			go func() {
				for ctx.Err() == nil {
					for _, ok := range BatchReadChannel(p.ctx, p.ch, math.MaxInt32) {
						// A non-OK value indicates that the channel was closed or the
						// context expired
						if !ok {
							closeDetected.Store(true)
							return
						}
						msgCount.Add(1)
					}
				}
			}()

			// EXPECT that all messages were read from the channel and that the explicit
			// close signal was detected.
			require.EventuallyWithT(t,
				func(c *assert.CollectT) {
					if !assert.True(c, closeDetected.Load()) {
						return
					}

					// in cases where we cancel the context, we may miss the last
					// few messages if the cancellation is detected before the
					// final messages are read, hence the tolerance
					assert.GreaterOrEqual(t, msgCount.Load(), int32(test.msgCount-test.tolerance))
				},
				5*time.Second,
				10*time.Millisecond)
		})
	}
}
