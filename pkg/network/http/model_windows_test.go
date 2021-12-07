// +build windows,npm

package http

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPath(t *testing.T) {
	tx := httpTX{
		RequestFragment: requestFragment(
			[]byte("GET /foo/bar?var1=value HTTP/1.1\nHost: example.com\nUser-Agent: example-browser/1.0"),
		),
	}

	b := make([]byte, HTTPBufferSize)
	assert.Equal(t, "/foo/bar", string(tx.Path(b)))
}

func TestPathHandlesNullTerminator(t *testing.T) {
	tx := httpTX{
		RequestFragment: requestFragment(
			[]byte("GET /foo/\x00bar?var1=value HTTP/1.1\nHost: example.com\nUser-Agent: example-browser/1.0"),
		),
	}

	b := make([]byte, HTTPBufferSize)
	assert.Equal(t, "/foo/", string(tx.Path(b)))
}

func TestLatency(t *testing.T) {
	tx := httpTX{
		ResponseLastSeen: 2e6,
		RequestStarted:   1e6,
	}
	// quantization brings it down
	assert.Equal(t, 999424.0, tx.RequestLatency())
}

func BenchmarkPath(b *testing.B) {
	tx := httpTX{
		RequestFragment: requestFragment(
			[]byte("GET /foo/bar?var1=value HTTP/1.1\nHost: example.com\nUser-Agent: example-browser/1.0"),
		),
	}

	b.ReportAllocs()
	b.ResetTimer()
	buf := make([]byte, HTTPBufferSize)
	for i := 0; i < b.N; i++ {
		_ = tx.Path(buf)
	}
	runtime.KeepAlive(buf)
}

func requestFragment(fragment []byte) [HTTPBufferSize]int8 {
	var b [HTTPBufferSize]int8
	for i := 0; i < len(b) && i < len(fragment); i++ {
		b[i] = int8(fragment[i])
	}
	return b
}