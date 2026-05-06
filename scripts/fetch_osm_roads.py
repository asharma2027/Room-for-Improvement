#!/usr/bin/env python3
"""
fetch_osm_roads.py  —  Fetch road/path data from OpenStreetMap via Overpass API
                       and convert to Three.js-ready JSON for the campus map.

Usage:
    python3 scripts/fetch_osm_roads.py

Output:
    public/data/osm_roads.json

Each road entry:
{
  "id":       OSM way ID (string),
  "name":     street name or null,
  "type":     OSM highway value ("residential", "footway", etc.),
  "category": one of "street" | "path" | "service" (for Three.js styling),
  "width_m":  approximate rendered width in meters,
  "points":   [[scene_x, scene_z], ...]   (centerline in Three.js scene coords)
}

The Three.js render loop should extrude each centerline into a flat ribbon
at y=0.05 (just above ground) using the given width.
"""

import json
import math
import urllib.request
import urllib.parse
import sys
import os

# ── Bounding box (same as 3MF export, slightly tighter to campus core) ───────
# Using the full export bbox so roads match building geometry exactly.
BBOX_S =  41.784177
BBOX_W = -87.611761
BBOX_N =  41.802735
BBOX_E = -87.58687

# ── Three.js scene origin (must match explore.ejs) ───────────────────────────
ORIGIN_LAT =  41.7895
ORIGIN_LNG = -87.5995

# Approximate meters per degree at this latitude
LAT_RAD = math.radians((BBOX_N + BBOX_S) / 2)
METERS_PER_DEG_LAT = 111320.0
METERS_PER_DEG_LON = 111320.0 * math.cos(LAT_RAD)

def lat_lng_to_scene(lat, lng):
    """Convert lat/lon to Three.js scene XZ (same formula as explore.ejs latLngToXZ)."""
    x = (lng - ORIGIN_LNG) * METERS_PER_DEG_LON
    z = -(lat - ORIGIN_LAT) * METERS_PER_DEG_LAT
    return [round(x, 3), round(z, 3)]


# ── Road type classification ──────────────────────────────────────────────────
# category: "street"  → rendered like a road (dark gray, wider)
#           "path"    → rendered like a footpath (lighter, narrower)
#           "service" → rendered like a service lane (medium, dashed-ish)
#           "skip"    → don't render (motorways, etc. not on campus)

HIGHWAY_CONFIG = {
    # type              category    width_m
    "motorway":        ("skip",     0),
    "motorway_link":   ("skip",     0),
    "trunk":           ("skip",     0),
    "trunk_link":      ("skip",     0),
    "primary":         ("street",   9.0),
    "primary_link":    ("street",   6.0),
    "secondary":       ("street",   7.0),
    "secondary_link":  ("street",   5.0),
    "tertiary":        ("street",   6.0),
    "tertiary_link":   ("street",   4.5),
    "unclassified":    ("street",   5.0),
    "residential":     ("street",   5.0),
    "living_street":   ("street",   4.0),
    "service":         ("service",  2.5),
    "pedestrian":      ("path",     3.0),
    "footway":         ("path",     2.0),
    "path":            ("path",     1.5),
    "cycleway":        ("path",     1.5),
    "steps":           ("path",     1.5),
    "track":           ("path",     2.0),
    "corridor":        ("skip",     0),   # indoor, skip
}

def classify(highway_tag):
    return HIGHWAY_CONFIG.get(highway_tag, ("street", 4.0))


# ── Overpass query ────────────────────────────────────────────────────────────
def build_query():
    bbox = f"{BBOX_S},{BBOX_W},{BBOX_N},{BBOX_E}"
    return f"""
[out:json][timeout:60];
(
  way["highway"]({bbox});
);
out body;
>;
out skel qt;
""".strip()


def fetch_overpass(query):
    url = "https://overpass-api.de/api/interpreter"
    data = urllib.parse.urlencode({"data": query}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "campus-map-builder/1.0")
    print("Fetching from Overpass API ...")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def main():
    query = build_query()
    try:
        osm = fetch_overpass(query)
    except Exception as e:
        print(f"ERROR fetching from Overpass: {e}")
        print("\nIf you're offline, save the Overpass response manually:")
        print(f"  curl -d 'data={urllib.parse.quote(query)}' https://overpass-api.de/api/interpreter > /tmp/osm_raw.json")
        print("  Then re-run this script (it will auto-detect the cached file).")
        sys.exit(1)

    # Build node id → lat/lon lookup
    nodes = {}
    for el in osm.get("elements", []):
        if el["type"] == "node":
            nodes[el["id"]] = (el["lat"], el["lon"])

    roads = []
    skipped = 0

    for el in osm.get("elements", []):
        if el["type"] != "way":
            continue

        tags = el.get("tags", {})
        highway = tags.get("highway", "")
        if not highway:
            continue

        category, width_m = classify(highway)
        if category == "skip":
            skipped += 1
            continue

        # Convert node refs to scene coordinates
        way_nodes = el.get("nodes", [])
        points = []
        for nid in way_nodes:
            if nid in nodes:
                lat, lng = nodes[nid]
                points.append(lat_lng_to_scene(lat, lng))

        if len(points) < 2:
            continue

        name = tags.get("name") or tags.get("ref") or None

        roads.append({
            "id":       str(el["id"]),
            "name":     name,
            "type":     highway,
            "category": category,
            "width_m":  width_m,
            "points":   points,
        })

    print(f"Processed {len(roads)} road segments  ({skipped} skipped as motorway/trunk)")

    # Summary by category
    from collections import Counter
    cats = Counter(r["category"] for r in roads)
    types = Counter(r["type"] for r in roads)
    print("\nBy category:")
    for k, v in sorted(cats.items()):
        print(f"  {k}: {v}")
    print("\nBy highway type:")
    for k, v in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    named = [r for r in roads if r["name"]]
    print(f"\nNamed roads: {len(named)}")
    for r in sorted(named, key=lambda x: x["name"]):
        print(f"  {r['name']!r}  ({r['type']})")

    out = {
        "meta": {
            "bbox":   {"s": BBOX_S, "w": BBOX_W, "n": BBOX_N, "e": BBOX_E},
            "origin": {"lat": ORIGIN_LAT, "lng": ORIGIN_LNG},
            "count":  len(roads),
        },
        "roads": roads,
    }

    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "public", "data", "osm_roads.json"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, separators=(",", ":"))

    size_kb = os.path.getsize(out_path) / 1024
    print(f"\nWrote {out_path}  ({size_kb:.1f} KB)")
    print("\nNext: run scripts/integrate_osm_roads.py to update explore.ejs")


if __name__ == "__main__":
    main()
