package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// The admin endpoint is local only and protected by a 0700 directory + 0600
// Unix socket. It never accepts config paths or configuration bodies from peers.
func startAdmin(path string, reload func(context.Context) error) (func(), error) {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("admin socket directory must be a real directory")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	if st, e = os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket path is not a socket")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	ln, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		ln.Close()
		return nil, e
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			http.Error(w, "reload request must have no body", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		if e := reload(ctx); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		fmt.Fprintln(w, "configuration reloaded")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = server.Serve(ln) }()
	return func() { _ = server.Close(); _ = os.Remove(path) }, nil
}

func runReload(args []string, out, errs io.Writer) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	fs.SetOutput(errs)
	socket := fs.String("socket", "/run/ssh-protecter/admin.sock", "local service control socket")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("reload requires local Linux root")
	}
	return requestReload(*socket, out)
}
func requestReload(socket string, out io.Writer) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequest("POST", "http://localhost/reload", nil)
	if e != nil {
		return e
	}
	response, e := client.Do(request)
	if e != nil {
		return fmt.Errorf("reload request failed; outcome may be unknown: %w", e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 8192))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 {
		return errors.New(string(body))
	}
	_, e = out.Write(body)
	return e
}
