package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// maxDatagram is the largest UDP payload; the receive buffer must hold it so
// that datagrams are never silently truncated.
const maxDatagram = 65535

// version is set at build time (-ldflags "-X main.version=v1.2.3") by the
// release workflow.
var version = "dev"

func main() {
	configPath := flag.String("config", defaultConfigFile, "path to config file")
	printLink := flag.Bool("print-link", false, "print the relay connection link and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("msstnetRelay31x", version)
		return
	}

	if *printLink {
		link, err := linkFromConfig(*configPath)
		if err != nil {
			log.Fatalf("print-link: %v", err)
		}
		fmt.Println(link)
		return
	}

	cfg, err := loadOrCreateConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := cfg.validate(); err != nil {
		log.Fatalf("config %s: %v", *configPath, err)
	}
	logFile, err := setupLogFile(cfg.Log.File, cfg.Log.MaxSizeMB, cfg.Log.MaxBackups)
	if err != nil {
		// Relaying matters more than the log file: go on with stderr only.
		log.Printf("log file %s: %v; logging to stderr only", cfg.Log.File, err)
	}
	defer logFile.Close()

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Relay.Bind)
	if err != nil {
		log.Fatalf("resolve bind addr %q: %v", cfg.Relay.Bind, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// Larger socket buffers absorb bursts under high load (e.g. iperf3).
	if err := conn.SetReadBuffer(cfg.Relay.SocketReadBuffer); err != nil {
		log.Printf("SetReadBuffer: %v", err)
	}
	if err := conn.SetWriteBuffer(cfg.Relay.SocketWriteBuffer); err != nil {
		log.Printf("SetWriteBuffer: %v", err)
	}
	log.Printf("msstnetRelay31x %s listening on udp/%s", version, conn.LocalAddr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	st := &stats{}

	// The relay key serves secure discovery and registration auth.
	priv, err := loadOrCreateRelayKey(cfg.Discovery.AuthKeyFile)
	if err != nil {
		log.Fatalf("relay key: %v", err)
	}
	auth := newSdiscAuth(priv)
	log.Printf("relay public key %s; mode=%s register_auth=%s", auth.publicKeyBase64(), cfg.Relay.Mode, cfg.Relay.RegisterAuth)
	if cfg.selfHosted() {
		log.Printf("connection link: %s", relayLink(cfg.Node.Addr, auth.pub, cfg.Relay.Password != ""))
		if cfg.Relay.Password != "" {
			warnIfReadable(*configPath, "config (holds relay.password)")
		}
	}
	if cfg.Relay.ProbeRate != 0 || cfg.Relay.ProbeBurst != 0 {
		log.Printf("relay.probe_rate/probe_burst are deprecated and ignored; 0x06/0x07 are no longer forwarded")
	}
	if cfg.Discovery.Enabled && !cfg.Discovery.RequireSenderInRoom {
		log.Printf("discovery: require_sender_in_room is deprecated and ignored; senders must always be room members")
	}

	var rooms roomPeerLookup
	var regKeys regKeyLookup
	if cfg.Control.ServerURL != "" {
		creds := newRelayCreds(cfg.selfHosted(), cfg.Control.RelaySecret)
		cc := newControlClient(cfg, creds, auth)
		wg.Go(func() { cc.run(ctx) })

		kc := newRegKeyCache(coordinatorKeyFetcher(cfg.Control.ServerURL, creds, &http.Client{Timeout: 5 * time.Second}),
			auth, cfg.Relay.DeviceKeyMaxEntries, cfg.Relay.DeviceKeyTTL, cfg.Relay.DeviceKeyStaleTTL)
		wg.Go(func() { kc.run(ctx, 5*time.Second) })
		regKeys = kc

		if cfg.Discovery.Enabled {
			httpc := &http.Client{Timeout: 3 * time.Second}
			rc := newRoomCache(coordinatorPeerFetcher(cfg.Control.ServerURL, creds, httpc), auth,
				cfg.Discovery.RoomCacheMaxEntries, cfg.Discovery.RoomCacheTTL, cfg.Discovery.RoomCacheStaleTTL)
			for range roomFetchWorkers {
				wg.Go(func() { rc.run(ctx, 3*time.Second) })
			}
			rooms = rc
		}
	} else {
		log.Printf("control.server_url is empty: not registering with a Coordinator; discovery forwarding and 0x0E registration disabled")
	}
	if cfg.Log.StatsInterval > 0 {
		wg.Go(func() { st.runReporter(ctx, cfg.Log.StatsInterval) })
	}

	// Closing the socket unblocks the read loop on shutdown.
	wg.Go(func() {
		<-ctx.Done()
		_ = conn.Close()
	})

	r := newRelay(conn, cfg.limits(), rooms, st)
	r.regKeys = regKeys
	serve(conn, r)

	stop()
	wg.Wait()
	st.report()
	log.Printf("relay stopped")
}

// linkFromConfig returns the connection link for an existing config: the
// address in node.addr and the relay key (created if missing, as on start).
func linkFromConfig(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	cfg, err := loadOrCreateConfig(path)
	if err != nil {
		return "", err
	}
	if err := cfg.validate(); err != nil {
		return "", fmt.Errorf("config %s: %w", path, err)
	}
	if err := checkHostPort(cfg.Node.Addr); err != nil {
		return "", fmt.Errorf("node.addr %q: %w", cfg.Node.Addr, err)
	}
	priv, err := loadOrCreateRelayKey(cfg.Discovery.AuthKeyFile)
	if err != nil {
		return "", err
	}
	return relayLink(cfg.Node.Addr, newSdiscAuth(priv).pub, cfg.Relay.Password != ""), nil
}

// warnIfReadable logs a warning if path is accessible by group or others.
func warnIfReadable(path, what string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: %s %s is accessible by group/others (mode %v); use 0600", what, path, fi.Mode().Perm())
	}
}

// serve runs the read loop until conn is closed. Packets are processed
// synchronously to preserve per-flow ordering: forwarding is a single
// non-blocking sendto, and spawning a goroutine per packet would let later
// packets overtake earlier ones (TCP-over-relay reordering).
func serve(conn *net.UDPConn, r *relay) {
	buf := make([]byte, maxDatagram)
	var lastErrLog time.Time
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient (e.g. ICMP-induced errors on some platforms). Log at
			// most once per second and avoid a hot spin on a persistent error.
			if now := time.Now(); now.Sub(lastErrLog) >= time.Second {
				log.Printf("read error: %v", err)
				lastErrLog = now
			}
			time.Sleep(time.Millisecond)
			continue
		}
		r.handle(buf[:n], src, time.Now())
	}
}
