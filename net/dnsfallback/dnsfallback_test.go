// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnsfallback

import (
	"context"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func TestGetDERPMap(t *testing.T) {
	// Oaken patch: the static map is intentionally empty — bootstrap DNS
	// candidates come only from the cached netmap map (supplied by Oaken's
	// control plane), never from Tailscale's public DERP list.
	dm := GetDERPMap()
	if dm == nil {
		t.Fatal("nil")
	}
	if len(dm.Regions) != 0 {
		t.Fatalf("static DERP map is not empty; got %d regions, want 0", len(dm.Regions))
	}
}

func TestCache(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "cache.json")

	// Write initial cache value
	initialCache := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "99a",
					RegionID: 99,
					HostName: "derp99a.tailscale.com",
					IPv4:     "1.2.3.4",
				}},
			},

			// Intentionally attempt to "overwrite" something
			1: {
				RegionID:   1,
				RegionCode: "r1",
				RegionName: "r1",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "1c",
					RegionID: 1,
					HostName: "derp1c.tailscale.com",
					IPv4:     "127.0.0.1",
					IPv6:     "::1",
				}},
			},
		},
	}
	d, err := json.Marshal(initialCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile, d, 0666); err != nil {
		t.Fatal(err)
	}

	// Clear any existing cached DERP map(s)
	cachedDERPMap.Store(nil)

	// Load the cache
	SetCachePath(cacheFile, t.Logf)
	if cm := cachedDERPMap.Load(); !reflect.DeepEqual(initialCache, cm) {
		t.Fatalf("cached map was %+v; want %+v", cm, initialCache)
	}

	// Verify that our DERP map is merged with the cache.
	dm := GetDERPMap()
	region, ok := dm.Regions[99]
	if !ok {
		t.Fatal("expected region 99")
	}
	if !reflect.DeepEqual(region, initialCache.Regions[99]) {
		t.Fatalf("region 99: got %+v; want %+v", region, initialCache.Regions[99])
	}

	// Oaken patch: with the static map empty, the cached map is the whole
	// result — the cache is authoritative, so region 1 passes through
	// unchanged. (Upstream used to refuse this override: a baked-in DERP
	// server could not be replaced by the cache. Oaken has no baked-in
	// servers, so there is nothing to protect.)
	n0 := dm.Regions[1].Nodes[0]
	if n0.IPv4 != "127.0.0.1" || n0.IPv6 != "::1" {
		t.Errorf("got %+v; expected the cached node to pass through unchanged", n0)
	}
}

func TestCacheUnchanged(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "cache.json")

	// Write initial cache value
	initialCache := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "99a",
					RegionID: 99,
					HostName: "derp99a.tailscale.com",
					IPv4:     "1.2.3.4",
				}},
			},
		},
	}
	d, err := json.Marshal(initialCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile, d, 0666); err != nil {
		t.Fatal(err)
	}

	// Clear any existing cached DERP map(s)
	cachedDERPMap.Store(nil)

	// Load the cache
	SetCachePath(cacheFile, t.Logf)
	if cm := cachedDERPMap.Load(); !reflect.DeepEqual(initialCache, cm) {
		t.Fatalf("cached map was %+v; want %+v", cm, initialCache)
	}

	// Remove the cache file on-disk, then re-set to the current value. If
	// our equality comparison is working, we won't rewrite the file
	// on-disk since the cached value won't have changed.
	if err := os.Remove(cacheFile); err != nil {
		t.Fatal(err)
	}

	UpdateCache(initialCache, t.Logf)
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatalf("got err=%v; expected to not find cache file", err)
	}

	// Now, update the cache with something slightly different and verify
	// that we did re-write the file on-disk.
	updatedCache := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes:      []*tailcfg.DERPNode{ /* set below */ },
			},
		},
	}
	clonedNode := *initialCache.Regions[99].Nodes[0]
	clonedNode.IPv4 = "1.2.3.5"
	updatedCache.Regions[99].Nodes = append(updatedCache.Regions[99].Nodes, &clonedNode)

	UpdateCache(updatedCache, t.Logf)
	if st, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("could not stat cache file; err=%v", err)
	} else if !st.Mode().IsRegular() || st.Size() == 0 {
		t.Fatalf("didn't find non-empty regular file; mode=%v size=%d", st.Mode(), st.Size())
	}
}

var extNetwork = flag.Bool("use-external-network", false, "use the external network in tests")

func TestLookup(t *testing.T) {
	if !*extNetwork {
		t.Skip("skipping test without --use-external-network")
	}

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	bus := eventbus.New()
	defer bus.Close()

	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatal(err)
	}

	resolver := &fallbackResolver{
		logf:           logf,
		netMon:         netMon,
		waitForCompare: true,
	}
	addrs, err := resolver.Lookup(context.Background(), "controlplane.tailscale.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("addrs: %+v", addrs)
}

// TestBootstrapDNSMapNilNetMon verifies that bootstrapDNSMap tolerates a nil
// netmon.Monitor. It used to panic in netns.NewDialer, which callers such as
// control/tsp hit under fault injection when their first dial failed.
func TestBootstrapDNSMapNilNetMon(t *testing.T) {
	// The context is already canceled so that no network I/O happens. The
	// panic, when it existed, fired before any I/O.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := bootstrapDNSMap(ctx, "derp1.tailscale.com", netip.MustParseAddr("192.0.2.1"), "controlplane.tailscale.com", t.Logf, nil, nil)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
}
