package daemon

import (
	"testing"
	"time"
)

// Guards the PIA-ghost diagnosis: with the tether up and every other utun idle
// (no inet lease), nothing legitimately owns DNS, so a resolver election stuck
// on a foreign nameserver is an orphan and must be swept. A genuinely connected
// VPN must not be swept.
func TestLiveTunnelDetection(t *testing.T) {
	const tetherOnly = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	inet 192.168.119.3 --> 192.168.119.8 netmask 0xffffff00
utun1: flags=80d4<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
	inet6 fe80::1d13:42e7:4bb1:afdb%utun1 prefixlen 64 scopeid 0x12
utun2: flags=80d4<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet6 fe80::26ed:ac9e:417:c444%utun2 prefixlen 64 scopeid 0x13
utun3: flags=80d4<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
	inet6 fe80::a97c:182a:7e40:ae8b%utun3 prefixlen 64 scopeid 0x14
en0: flags=8863<UP,BROADCAST,SMARTHAVES,RUNNING,MULTICAST> mtu 1500
	ether 3c:06:3c:5b:1a:2c
`

	const vpnConnected = tetherOnly + `utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
	inet 10.18.0.6 --> 10.18.0.7 netmask 0xff000000
`

	const ourTunnelOnly = `utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	inet 192.168.119.3 --> 192.168.119.8 netmask 0xffffff00
utun1: flags=80d4<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
	inet6 fe80::a97c:182a:7e40:ae8b%utun1 prefixlen 64 scopeid 0x14
`

	cases := []struct {
		name     string
		out      string
		ourIface string
		want     bool
	}{
		{"tether up, other utuns idle: no tunnel owns DNS", tetherOnly, "utun0", false},
		{"connected VPN tunnel owns DNS", vpnConnected, "utun0", true},
		{"our own lease is not a foreign tunnel", ourTunnelOnly, "utun4", false},
		{"empty output", "", "utun0", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := liveTunnelFromIfconfig(tc.out, tc.ourIface); got != tc.want {
				t.Fatalf("liveTunnelFromIfconfig() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldSweepDNS(t *testing.T) {
	now := time.Date(2026, 10, 8, 16, 34, 0, 0, time.UTC)

	cases := []struct {
		name       string
		streak     int
		lastSweep  time.Time
		liveTunnel bool
		want       bool
	}{
		{"below the grace period keeps re-registering only", dnsSweepAfterTicks - 1, time.Time{}, false, false},
		{"grace period elapsed with no tunnel: sweep the orphan", dnsSweepAfterTicks, time.Time{}, false, true},
		{"a connected VPN owns DNS by design: never sweep", dnsSweepAfterTicks * 3, time.Time{}, true, false},
		{"cooldown blocks a second sweep", dnsSweepAfterTicks * 3, now.Add(-1 * time.Minute), false, false},
		{"after the cooldown a repeat sweep is allowed", dnsSweepAfterTicks * 3, now.Add(-dnsSweepCooldown - time.Minute), false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldSweepDNS(tc.streak, tc.lastSweep, now, tc.liveTunnel); got != tc.want {
				t.Fatalf("shouldSweepDNS() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Pins the detection half against the real captures from the 2026-10-08 PIA
// ghost outage: DroidTether's service was still the elected primary and its
// DNS was still in the store, but resolver #1 carried the VPN's dead
// nameserver and 1.1.1.1 was missing from the published resolvers entirely —
// the state where re-registering cannot win and a sweep is required.
func TestDNSIntactDetectsForeignResolver(t *testing.T) {
	const primary = `<dictionary> {
  PrimaryInterface : utun0
  PrimaryService : droidtether
  Router : 192.168.119.8
}`

	const healthy = `resolver #1
  nameserver[0] : 1.1.1.1
  nameserver[1] : 192.168.119.8
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
resolver #2
  nameserver[0] : 1.1.1.1
  nameserver[1] : 192.168.119.8
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
`

	const orphanedVPN = `resolver #1
  search domain[0] : openvpn
  nameserver[0] : 10.0.0.243
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
resolver #2
  nameserver[0] : 10.0.0.243
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
`

	const supplementalOnly = `resolver #1
  nameserver[0] : 1.1.1.1
  nameserver[1] : 192.168.119.8
  flags    : Supplemental
  reach    : 0x00000002 (Reachable)
`

	cases := []struct {
		name      string
		primary   string
		resolvers string
		want      bool
	}{
		{"healthy tunnel resolvers", primary, healthy, true},
		{"dead VPN nameserver owns resolver #1", primary, orphanedVPN, false},
		{"Supplemental-only resolver suppresses A queries", primary, supplementalOnly, false},
		{"another service is elected primary", `<dictionary> {
  PrimaryInterface : en0
  PrimaryService : com.apple.airport
  Router : 192.168.1.1
}`, healthy, false},
		{"no resolver at all", primary, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsIntactFrom(tc.primary, tc.resolvers); got != tc.want {
				t.Fatalf("dnsIntactFrom() = %v, want %v", got, tc.want)
			}
		})
	}
}
