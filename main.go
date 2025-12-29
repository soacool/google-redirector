package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// 1. Buffer Pool: Reduces GC pressure by reusing byte slices
var bufferPool = sync.Pool{
	New: func() interface{} {
		// 32KB buffer is standard for io.Copy
		b := make([]byte, 32*1024)
		return &b
	},
}

func main() {
	backendURL := getEnv("BACKEND_URL", "https://funtones-orange.run.place")

	target, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Failed to parse BACKEND_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// 2. Transport Tuning: Optimize connection reuse for HTTP requests
	proxy.Transport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        1000,             // Default is 100, too low for high load
		MaxIdleConnsPerHost: 1000,             // Default is 2, massive bottleneck
		IdleConnTimeout:     90 * time.Second, // Keep connections open longer
		DisableCompression:  true,             // CPU optimization: don't compress if backend already did
	}

	// 3. Removed Logging from Director (Hot Path)
	// Only modifying the request, not logging every single hit to stdout
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Optimization: Removed log.Printf here to reduce I/O blocking
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
		rw.Write([]byte("Bad Gateway"))
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketRequest(r) {
			handleWebSocket(w, r, target)
		} else {
			proxy.ServeHTTP(w, r)
		}
	})

	log.Printf("High-performance redirector starting on port 8080")
	log.Printf("Proxying to: %s", backendURL)

	// ListenAndServe
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func isWebSocketRequest(r *http.Request) bool {
	// 4. Optimization: Use EqualFold to avoid allocating new strings with ToLower
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL) {
	// Optimization: Removed info log to reduce I/O

	// Build backend WebSocket URL
	// We construct this manually to avoid deep copying the URL object unnecessarily
	backendScheme := "ws"
	if target.Scheme == "https" {
		backendScheme = "wss"
	}

	backendURL := &url.URL{
		Scheme:   backendScheme,
		Host:     target.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	backendConn, backendResp, err := dialBackendWebSocket(backendURL, r)
	if err != nil {
		log.Printf("Backend WebSocket dial failed: %v", err)
		http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	if err := writeSwitchingProtocols(clientConn, r, backendResp); err != nil {
		clientConn.Close()
		return
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go pipe(backendConn, clientConn, &wg)
	go pipe(clientConn, backendConn, &wg)

	wg.Wait()
}

func dialBackendWebSocket(u *url.URL, r *http.Request) (net.Conn, *http.Response, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Optimization: Reduced timeout for faster failover
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	if u.Scheme == "wss" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, nil, err
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: make(http.Header),
		Host:   u.Host,
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	// Forward headers directly without extra logic where possible
	req.Header.Set("Sec-WebSocket-Version", r.Header.Get("Sec-WebSocket-Version"))
	req.Header.Set("Sec-WebSocket-Key", r.Header.Get("Sec-WebSocket-Key"))

	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		req.Header.Set("Sec-WebSocket-Protocol", proto)
	}
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		req.Header.Set("Sec-WebSocket-Extensions", ext)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Optimization: Use a smaller buffered reader if headers are small,
	// but default is fine.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, fmt.Errorf("expected 101, got %d", resp.StatusCode)
	}

	return conn, resp, nil
}

func writeSwitchingProtocols(clientConn net.Conn, clientReq *http.Request, backendResp *http.Response) error {
	accept := backendResp.Header.Get("Sec-WebSocket-Accept")
	if accept == "" {
		return fmt.Errorf("missing Sec-WebSocket-Accept")
	}

	// Optimization: Pre-calculate size or use string builder if this gets complex,
	// but simple string concat is fast enough here for one-time op.
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	sb.WriteString("Upgrade: websocket\r\n")
	sb.WriteString("Connection: Upgrade\r\n")
	sb.WriteString("Sec-WebSocket-Accept: ")
	sb.WriteString(accept)
	sb.WriteString("\r\n")

	if proto := clientReq.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		backendProto := backendResp.Header.Get("Sec-WebSocket-Protocol")
		if backendProto != "" {
			// Skip the strings.Contains check if we trust the backend,
			// otherwise keep it.
			sb.WriteString("Sec-WebSocket-Protocol: ")
			sb.WriteString(backendProto)
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("\r\n")

	_, err := clientConn.Write([]byte(sb.String()))
	return err
}

func pipe(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	// 5. Critical Optimization: Use Buffer Pool + CopyBuffer
	// Get buffer from pool
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr) // Return to pool when done

	// Dereference to get the slice
	buf := *bufPtr

	// io.CopyBuffer prevents allocating a new buffer for every single connection
	_, err := io.CopyBuffer(dst, src, buf)

	// Logging removed from hot path. Only log unexpected errors if strictly necessary.
	if err != nil {
		// Only log real errors, ignore standard close errors
		// This string check is expensive, so only do it if err != nil
		if !strings.Contains(err.Error(), "closed network connection") {
			log.Printf("pipe error: %v", err)
		}
	}

	// Fast Close
	// We set a deadline to force any pending reads/writes to unblock immediately
	_ = dst.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))

	// Send WS Close frame (Opcode 8)
	_, _ = dst.Write([]byte{0x88, 0x02, 0x03, 0xe8})

	if tc, ok := dst.(*tls.Conn); ok {
		_ = tc.Close()
	} else {
		if sc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = sc.CloseWrite()
		}
		_ = dst.Close()
	}
}
