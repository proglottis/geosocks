package main

import (
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"

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

type tunnel struct {
	Network string
	Address string
	Config  *ssh.ClientConfig
	IPV6    bool

	zones []string

	mu     sync.Mutex
	client *ssh.Client
}

func (t *tunnel) getClient() (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	if t.client == nil {
		t.client, err = ssh.Dial(t.Network, t.Address, t.Config)
	}
	return t.client, err
}

func (t *tunnel) removeClient() {
	t.mu.Lock()
	defer t.mu.Unlock()
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
	if ok && d.Tunnel.Contains(name) {
		log.Printf("Tunnel: %s", name)
		return d.Tunnel.Dial(ctx, network, addr)
	}
	log.Printf("Direct: %s", name)
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
	if r.preferIPV6(name) {
		for _, ip := range ips {
			if ip.To4() == nil {
				return ctx, ip, nil
			}
		}
	}
	for _, ip := range ips {
		return ctx, ip, nil
	}
	return ctx, nil, errors.New("could not resolve")
}

func (r resolver) preferIPV6(name string) bool {
	return r.Tunnel.Contains(name) && r.Tunnel.IPV6
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
		Network: "tcp",
		Address: cfg.Key("address").String(),
		Config:  &ssh.ClientConfig{User: cfg.Key("user").String(), Auth: auth},
		IPV6:    cfg.Key("ipv6").MustBool(),
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
