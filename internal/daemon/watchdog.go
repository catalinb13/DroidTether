package daemon

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/princePal/droidtether/internal/tun"
)

// Config watchdog: macOS standby can silently remove the injected split
// default routes (0.0.0.0/1, 128.0.0.0/1), the dynamic-store DNS entries, and
// even the utun IP configuration — while the USB/RNDIS session survives the
// wake, so no new DHCP event fires and the original injection in OnDHCP never
// runs again. The result is a tethered-but-dead network: interface up, pipe
// to the phone alive, but no route past it and no name resolution.
//
// This watchdog verifies every few seconds that the injected config is still
// in place and re-applies whatever is missing. All checks are local
// syscalls/commands (route/ifconfig/scutil) — zero carrier data.

// A third failure mode is an orphaned DNS registration: a VPN helper that
// exits without withdrawing its nameserver leaves configd electing a dead
// resolver forever, so re-registering our own DNS every tick never wins. The
// watchdog sweeps that orphan by signalling configd — but only when no live
// tunnel is present, because a connected VPN owning DNS is intended behaviour.

// routeIntact reports whether the split default routes (0.0.0.0/1 and
// 128.0.0.0/1) are still installed on the given utun interface.
//
// It must NOT check `route -n get default`: DroidTether deliberately injects
// the two /1 split routes instead of a real default route, so a `default`
// query resolves to whatever real interface owns it (en0/Wi-Fi, en1/Ethernet)
// and the check fails forever — a permanent false positive that re-injected
// the routes every tick and spammed route(8) errors. Verify the routes we
// actually install.
func routeIntact(ifaceName string) bool {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return false
	}
	return routeIntactFromTable(string(out), ifaceName)
}

// routeIntactFromTable holds the parsing logic, separated from the exec so it
// is unit-testable.
func routeIntactFromTable(table, ifaceName string) bool {
	// Both halves must be present on our interface; one alone leaves a
	// black hole for the other half of the IPv4 space.
	for _, prefix := range []string{"0/1", "128.0/1"} {
		found := false
		for _, line := range strings.Split(table, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != prefix {
				continue
			}
			if fields[len(fields)-1] == ifaceName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// dnsIntact reports whether DroidTether's DNS is healthy end-to-end:
// configd still considers the droidtether service the primary (Global/IPv4
// PrimaryService) and mDNSResponder's first resolver carries both our
// nameserver and the RequestA bit. Checking the derived resolver via
// `scutil --dns` instead of the raw store dict matters: a raw
// State:/Network/Global/DNS write can show __FLAGS__ with the A bit set
// while mDNSResponder still only has a Supplemental-only resolver and
// suppresses every A/AAAA query (getaddrinfo fails despite a "good" store).
func dnsIntact() bool {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("show State:/Network/Global/IPv4\nquit\n")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	dns, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return false
	}
	return dnsIntactFrom(string(out), string(dns))
}

// dnsIntactFrom holds the parsing logic, separated from the exec so it is
// unit-testable.
func dnsIntactFrom(globalIPv4, resolverList string) bool {
	if !strings.Contains(globalIPv4, "PrimaryService : droidtether") {
		return false
	}
	start := strings.Index(resolverList, "resolver #1")
	if start < 0 {
		return false
	}
	block := resolverList[start:]
	if end := strings.Index(block, "resolver #2"); end >= 0 {
		block = block[:end]
	}
	return strings.Contains(block, "1.1.1.1") && strings.Contains(block, "Request A records")
}

// dnsSweepAfterTicks is how many consecutive failed DNS checks — each already
// followed by a re-registration — are tolerated before configd is asked to
// rebuild its DNS registry. At the default 10s interval that is a one-minute
// grace period for ordinary transient races (standby wake, interface churn).
const dnsSweepAfterTicks = 6

// dnsSweepCooldown throttles the sweep. When another service legitimately owns
// DNS, re-signalling configd on every tick would be pure churn.
const dnsSweepCooldown = 5 * time.Minute

// liveTunnelFromIfconfig reports whether an interface other than ours is a
// live tunnel: a utun-family interface that is not ours and holds an IPv4
// lease. A connected VPN client (PIA, OpenVPN, WireGuard) owns the system DNS
// by design and its resolver must be left alone; only a tunnel whose interface
// is gone while its DNS registration stayed behind is an orphan. Idle
// utun-family interfaces carry no inet address and do not count.
func liveTunnelFromIfconfig(out, ourIface string) bool {
	name := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			name = strings.TrimSuffix(strings.Fields(line)[0], ":")
			continue
		}
		if name == "" || name == ourIface || !strings.HasPrefix(name, "utun") {
			continue
		}
		// "inet ", not "inet6": an IPv4 lease means the tunnel is up.
		if strings.Contains(line, "inet ") {
			return true
		}
	}
	return false
}

// shouldSweepDNS decides whether a DNS failure is a stuck election worth a
// configd rebuild. Re-registration alone is not enough: a VPN that withdrew
// its interface but not its resolver leaves configd electing the dead
// nameserver indefinitely. liveTunnel suppresses the sweep while a real tunnel
// is connected.
func shouldSweepDNS(failStreak int, lastSweep, now time.Time, liveTunnel bool) bool {
	if liveTunnel || failStreak < dnsSweepAfterTicks {
		return false
	}
	if !lastSweep.IsZero() && now.Sub(lastSweep) < dnsSweepCooldown {
		return false
	}
	return true
}

// sweepConfigDNS sends SIGHUP to configd so it rebuilds its DNS registry from
// the live interfaces and preferences, dropping orphaned resolver registrations
// so the service that is actually up wins the election again. `launchctl
// kickstart -k system/com.apple.configd` is refused under SIP (rc 150); the
// signal is permitted and configd stays up.
func sweepConfigDNS() error {
	return exec.Command("pkill", "-HUP", "configd").Run()
}

// ifaceConfigIntact reports whether the utun interface still holds the DHCP
// lease address (ifconfig <name> <local> <remote> mtu <val>).
func ifaceConfigIntact(ifaceName, localIP string) bool {
	out, err := exec.Command("ifconfig", ifaceName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "inet "+localIP)
}

// startConfigWatchdog launches the watchdog goroutine for an active session.
// It is bound to ctx, so it stops together with the relay session.
func (d *Daemon) startConfigWatchdog(ctx context.Context, iface tun.Interface, localIP, gateway, mtu string) {
	interval := time.Duration(d.cfg.Route.WatchdogIntervalS) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	log.Info().
		Str("component", "watchdog").
		Dur("interval", interval).
		Msg("Config watchdog started — will re-apply route/DNS/interface if macOS removes them (e.g. standby)")

	go func() {
		// dnsFailStreak counts failed DNS checks that a re-registration already
		// followed; lastDNS is when the last orphan sweep signalled configd.
		dnsFailStreak := 0
		lastDNS := time.Time{}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			name := iface.Name()

			// Interface config first: route/DNS injection and the relay
			// itself are useless without the lease address.
			if !ifaceConfigIntact(name, localIP) {
				log.Warn().
					Str("component", "watchdog").
					Str("interface", name).
					Msg("Interface IP config was removed — re-applying ifconfig...")
				if err := iface.Configure(localIP, gateway, mtu); err != nil {
					log.Error().Str("component", "watchdog").Err(err).Msg("Failed to re-apply interface config")
					continue
				}
			}

			if !d.cfg.Route.SetDefaultRoute {
				continue
			}

			if !routeIntact(name) {
				log.Warn().
					Str("component", "watchdog").
					Str("interface", name).
					Msg("Default route no longer resolves through DroidTether — re-injecting split default routes...")
				if err := iface.SetDefaultRoute(gateway); err != nil {
					log.Error().Str("component", "watchdog").Err(err).Msg("Failed to re-inject default route")
				}
			}

			if dnsIntact() {
				dnsFailStreak = 0
				continue
			}

			dnsFailStreak++
			log.Warn().
				Str("component", "watchdog").
				Int("consecutive_dns_failures", dnsFailStreak).
				Msg("DroidTether DNS resolver broken (primary election or RequestA lost) — re-registering service and re-injecting DNS...")
			if err := iface.RegisterService(localIP, gateway); err != nil {
				log.Error().Str("component", "watchdog").Err(err).Msg("Failed to re-register service with configd")
			}
			if err := iface.SetDNS([]string{"1.1.1.1", gateway}); err != nil {
				log.Error().Str("component", "watchdog").Err(err).Msg("Failed to re-inject DNS")
			}

			// Re-registering did not win the election. When no other tunnel is
			// actually up, the foreign nameserver we are losing to belongs to a
			// VPN that withdrew its interface without withdrawing its resolver
			// registration: sweep the orphan instead of spinning forever.
			out, err := exec.Command("ifconfig", "-a").Output()
			if err != nil {
				continue
			}
			if shouldSweepDNS(dnsFailStreak, lastDNS, time.Now(), liveTunnelFromIfconfig(string(out), name)) {
				lastDNS = time.Now()
				log.Warn().
					Str("component", "watchdog").
					Msg("DNS election still stuck on a foreign nameserver with no live tunnel — orphaned resolver from a VPN that exited uncleanly; asking configd to rebuild its DNS registry (SIGHUP)...")
				if err := sweepConfigDNS(); err != nil {
					log.Error().Str("component", "watchdog").Err(err).Msg("Failed to signal configd")
				}
			}
		}
	}()
}

// startLinkWatchdog probes the phone's gateway through the tunnel. When
// Android disables USB tethering (e.g. the phone screen locks), the phone
// re-enumerates without the RNDIS config and the relay's writes to the
// dead handle keep "succeeding" — the session becomes a zombie that holds
// the watcher's active-device slot, so a later re-enable never re-attaches.
// Three consecutive failed probes end the session; the watcher then sees
// the device again (or waits for the user to re-enable tethering, covered
// by the handshake-failure notification).
func (d *Daemon) startLinkWatchdog(ctx context.Context, relay *Relay, gateway, client string) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		fails := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := exec.Command("ping", "-c", "1", "-t", "3", "-S", client, gateway).Run()
				if err == nil {
					fails = 0
					continue
				}
				fails++
				if fails < 3 {
					log.Warn().Str("component", "watchdog").
						Int("fails", fails).
						Msg("Gateway ping failed")
					continue
				}
				log.Error().Str("component", "watchdog").
					Msg("Phone left tethering state; ending zombie session")
				relay.Stop()
				return
			}
		}
	}()
}
