package main

import (
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"
)

type key int

const (
	nameKey key = iota
)

type ipv6Option int

const (
	defaultIPV6 ipv6Option = iota
	preferIPV6
	forceIPV6
)

func parseIPV6Option(str string) (ipv6Option, error) {
	switch strings.ToLower(str) {
	case "0", "f", "false", "no", "n", "off", "default":
		return defaultIPV6, nil
	case "1", "t", "true", "yes", "y", "on", "prefer":
		return preferIPV6, nil
	case "force":
		return forceIPV6, nil
	}
	return defaultIPV6, errors.New("invalid IPV6 option")
}

func mustParseIPV6Option(str string) ipv6Option {
	val, err := parseIPV6Option(str)
	if err != nil {
		panic(err)
	}
	return val
}

type tunnel struct {
	Network     string
	Address     string
	Config      *ssh.ClientConfig
	IPV6        ipv6Option
	IdleTimeout time.Duration

	zones []string

	mu     sync.Mutex
	client *ssh.Client
	timer  *time.Timer
}

func (t *tunnel) getClient() (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	if t.client == nil {
		log.Printf("tunnel: Opening SSH connection")
		t.client, err = ssh.Dial(t.Network, t.Address, t.Config)
		t.timer = time.AfterFunc(t.IdleTimeout, t.removeClient)
	}
	t.timer.Reset(t.IdleTimeout)
	return t.client, err
}

func (t *tunnel) removeClient() {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.Printf("tunnel: Closing SSH connection")
	if t.client == nil {
		return
	}
	t.timer.Stop()
	t.client.Close()
	t.client = nil
}

func (t *tunnel) Contains(name string) bool {
	for _, zone := range t.zones {
		if strings.HasSuffix(name, zone) || name == zone[1:] {
			return true
		}
	}
	return false
}

func (t *tunnel) AddZone(zone string) {
	if !strings.HasPrefix(zone, ".") {
		zone = "." + zone
	}
	t.zones = append(t.zones, zone)
}

func (t *tunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	client, err := t.getClient()
	if err != nil {
		return nil, err
	}
	conn, err := client.Dial(network, addr)
	if err != nil {
		t.removeClient()
	}
	return conn, err
}

type dialer struct {
	Tunnel *tunnel
	Dialer func(network, addr string) (net.Conn, error)
}

func (d dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	name, ok := ctx.Value(nameKey).(string)
	if !ok {
		name = addr
	}
	if d.Tunnel.Contains(name) {
		log.Printf("dialer: Tunnel: %s", name)
		return d.Tunnel.Dial(ctx, network, addr)
	}
	log.Printf("dialer: Direct: %s", name)
	return d.Dialer(network, addr)
}

type resolver struct {
	Tunnel *tunnel
}

func (r resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ctx = context.WithValue(ctx, nameKey, name)
	ips, err := net.LookupIP(name)
	if err != nil {
		return ctx, nil, err
	}
	var ipv6 ipv6Option
	if r.Tunnel.Contains(name) {
		ipv6 = r.Tunnel.IPV6
		if ipv6 == preferIPV6 || ipv6 == forceIPV6 {
			for _, ip := range ips {
				if ip.To4() == nil {
					return ctx, ip, nil
				}
			}
		}
	}
	if ipv6 != forceIPV6 {
		for _, ip := range ips {
			return ctx, ip, nil
		}
	}
	return ctx, nil, errors.New("could not resolve")
}

func newTunnel(cfg *ini.Section) *tunnel {
	var auth []ssh.AuthMethod
	if cfg.HasKey("password") {
		auth = append(auth, ssh.Password(cfg.Key("password").String()))
	}
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}
	t := &tunnel{
		Network:     "tcp",
		Address:     cfg.Key("address").String(),
		Config:      &ssh.ClientConfig{User: cfg.Key("user").String(), Auth: auth},
		IPV6:        mustParseIPV6Option(cfg.Key("ipv6").MustString("no")),
		IdleTimeout: cfg.Key("idle_timeout").MustDuration(30 * time.Minute),
	}
	for _, zone := range cfg.Key("zones").Strings(",") {
		t.AddZone(zone)
	}
	return t
}

func main() {
	cfg, err := ini.Load("config")
	if err != nil {
		log.Fatalf("Config: %s", err)
	}
	tunnel := newTunnel(cfg.Section("tunnel"))
	dialer := dialer{
		Tunnel: tunnel,
		Dialer: net.Dial,
	}
	server, err := socks5.New(&socks5.Config{
		Dial:     dialer.Dial,
		Resolver: resolver{Tunnel: tunnel},
	})
	if err != nil {
		log.Fatalf("Setup: %s", err)
	}
	address := cfg.Section("local").Key("address").String()
	log.Printf("Starting on %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		log.Fatalf("Listen: %s", err)
	}
}
