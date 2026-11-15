package app

// Autoteste: real connections made by AionWG itself. Its own sockets are
// always routed through the tunnel, so this checks the exact path the game
// and Steam use.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type TestResult struct {
	Name   string
	OK     bool
	Detail string
	Dur    time.Duration
}

func buildDNSQuery(name string, id uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1) // A, IN
}

func dnsUDP(server, name string) (int, error) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	q := buildDNSQuery(name, 0x4157)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("sem resposta (%v)", err)
	}
	if n < 12 || binary.BigEndian.Uint16(buf) != 0x4157 {
		return 0, fmt.Errorf("resposta inválida")
	}
	if rc := buf[3] & 0x0f; rc != 0 {
		return 0, fmt.Errorf("rcode %d", rc)
	}
	return int(binary.BigEndian.Uint16(buf[6:])), nil
}

func newTestClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext:         (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
		},
	}
}

// runSelfTest runs every check and reports each result as it finishes.
func runSelfTest(dnsServer, vpnIP string, report func(TestResult)) {
	hc := newTestClient()
	run := func(name string, f func() (string, error)) {
		t0 := time.Now()
		d, err := f()
		r := TestResult{Name: name, OK: err == nil, Detail: d, Dur: time.Since(t0)}
		if err != nil {
			r.Detail = err.Error()
		}
		report(r)
	}
	get := func(url string, limit int64) (int, int64, error) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 AionWG-selftest")
		resp, err := hc.Do(req)
		if err != nil {
			return 0, 0, err
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
		return resp.StatusCode, n, err
	}

	if dnsServer == "" {
		dnsServer = "1.1.1.1"
	}
	run("DNS "+dnsServer+" (UDP pelo túnel)", func() (string, error) {
		n, err := dnsUDP(dnsServer, "api.steampowered.com")
		return fmt.Sprintf("%d respostas", n), err
	})
	run("DNS do Windows", func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupHost(ctx, "api.steampowered.com")
		if err != nil {
			return "", err
		}
		return strings.Join(ips, ", "), nil
	})
	run("IP de saída", func() (string, error) {
		resp, err := hc.Get("https://1.1.1.1/cdn-cgi/trace")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		kv := map[string]string{}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), "="); ok {
				kv[k] = v
			}
		}
		d := fmt.Sprintf("%s (Cloudflare %s, %s)", kv["ip"], kv["colo"], kv["loc"])
		if vpnIP != "" && kv["ip"] != vpnIP {
			d += " — diferente do endpoint " + vpnIP + " (normal se o VPS sai por outro IP)"
		}
		return d, nil
	})
	run("Steam API (CM list)", func() (string, error) {
		code, n, err := get("https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0", 1<<20)
		if err == nil && code != 200 {
			err = fmt.Errorf("HTTP %d", code)
		}
		return fmt.Sprintf("HTTP %d, %d KB", code, n/1024), err
	})
	run("Steam loja", func() (string, error) {
		code, n, err := get("https://store.steampowered.com/", 4<<20)
		if err == nil && code >= 400 {
			err = fmt.Errorf("HTTP %d (a Steam pode estar bloqueando o IP do VPS)", code)
		}
		return fmt.Sprintf("HTTP %d, %d KB", code, n/1024), err
	})
	run("Download 5 MB", func() (string, error) {
		t0 := time.Now()
		code, n, err := get("https://speed.cloudflare.com/__down?bytes=5000000", 6<<20)
		if err == nil && code != 200 {
			err = fmt.Errorf("HTTP %d", code)
		}
		mbps := float64(n*8) / time.Since(t0).Seconds() / 1e6
		return fmt.Sprintf("%.1f Mbit/s", mbps), err
	})
	run("Upload 2 MB", func() (string, error) {
		body := make([]byte, 2_000_000)
		rand.Read(body)
		t0 := time.Now()
		req, _ := http.NewRequest("POST", "https://speed.cloudflare.com/__up", bytes.NewReader(body))
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		mbps := float64(len(body)*8) / time.Since(t0).Seconds() / 1e6
		return fmt.Sprintf("%.1f Mbit/s", mbps), nil
	})
}
