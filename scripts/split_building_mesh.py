#!/usr/bin/env python3
"""
split_building_mesh.py
======================
Walks the triangle-adjacency graph of the single merged building mesh in
3mf_extract.json and groups disconnected islands into separate buildings.

Each island = one building.

Output: public/data/3mf_buildings.json
  {
    "meta": { ...same as source... },
    "buildings": [
      {
        "id": "building_0042",
        "centroid_lat": 41.7855,
        "centroid_lon": -87.6003,
        "matched_name": "Burton-Judson",   // or "unknown"
        "matched_category": "dorm",        // or "unknown"
        "vertex_count": 312,
        "triangle_count": 624,
        "vertices": [[x,y,z], ...],        // local coords (meters from origin)
        "triangles": [[i,j,k], ...]        // indices into this island's vertices
      },
      ...
    ]
  }

Matching: each island centroid is compared against the DORMS + LANDMARKS
arrays hard-coded below (mirrored from explore.ejs).  If the nearest entry
is within MATCH_RADIUS_M metres the island is labelled with that name.
"""

import json
import sys
import math
import time
from collections import defaultdict

# ── tunables ──────────────────────────────────────────────────────────────────
INPUT_PATH   = "public/data/3mf_extract.json"
OUTPUT_PATH  = "public/data/3mf_buildings.json"
MATCH_RADIUS_M = 40          # metres — max centroid distance to claim a match
MIN_TRIANGLES  = 4           # islands smaller than this are noise; skip them

# ── known buildings (mirrored from explore.ejs DORMS + LANDMARKS) ─────────────
KNOWN_BUILDINGS = [
    # Dorms
    {"name": "Burton-Judson",              "category": "dorm",    "lat": 41.7855031698, "lon": -87.6003483856},
    {"name": "I-House",                    "category": "dorm",    "lat": 41.7882362427, "lon": -87.5908153883},
    {"name": "Snell-Hitchcock",            "category": "dorm",    "lat": 41.7911141668, "lon": -87.6008801585},
    {"name": "Max Palevsky",               "category": "dorm",    "lat": 41.7929,       "lon": -87.5998},
    {"name": "Campus North",               "category": "dorm",    "lat": 41.7948207035, "lon": -87.5991278838},
    {"name": "Renee Granville-Grossman",   "category": "dorm",    "lat": 41.7845934364, "lon": -87.6003320148},
    {"name": "Woodlawn",                   "category": "dorm",    "lat": 41.7846551855, "lon": -87.5970075112},
    # Libraries
    {"name": "Regenstein",                 "category": "library", "lat": 41.7922131882, "lon": -87.5999558277},
    {"name": "Crerar",                     "category": "library", "lat": 41.7905519198, "lon": -87.6028134134},
    {"name": "Harper Memorial",            "category": "library", "lat": 41.7879911699, "lon": -87.5996176668},
    {"name": "Eckhart",                    "category": "library", "lat": 41.7902601919, "lon": -87.5985446188},
    # Dining
    {"name": "Bartlett",                   "category": "dining",  "lat": 41.7919480829, "lon": -87.5984764408},
    {"name": "Cathey Dining",              "category": "dining",  "lat": 41.7850932274, "lon": -87.6003608561},
    {"name": "Baker Dining",               "category": "dining",  "lat": 41.7945528291, "lon": -87.5991870748},
    # Gyms
    {"name": "Ratner",                     "category": "gym",     "lat": 41.794167286,  "lon": -87.6020612031},
    {"name": "Crown Field House",          "category": "gym",     "lat": 41.7935651382, "lon": -87.5989484493},
    # Culture / landmarks
    {"name": "Rockefeller Chapel",         "category": "culture", "lat": 41.7885326920, "lon": -87.5970532895},
    {"name": "Ida Noyes",                  "category": "culture", "lat": 41.7881890814, "lon": -87.5955909701},
    {"name": "Smart / Court",              "category": "museum",  "lat": 41.7939912382, "lon": -87.6008685227},
    {"name": "ISAC",                       "category": "museum",  "lat": 41.7892412689, "lon": -87.5975070637},
    {"name": "Robie House",                "category": "museum",  "lat": 41.7898221087, "lon": -87.5959799364},
    {"name": "Hutchinson / Reynolds",      "category": "culture", "lat": 41.791187641,  "lon": -87.5987583775},
    {"name": "Harper Center",              "category": "building","lat": 41.7890476108, "lon": -87.5954799992},
    {"name": "Bond Chapel",                "category": "culture", "lat": 41.7887021038, "lon": -87.600419112},
    {"name": "Saieh Hall",                 "category": "building","lat": 41.7899775048, "lon": -87.5971765036},
    {"name": "Cobb Hall",                  "category": "building","lat": 41.7889809149, "lon": -87.6009443458},
    {"name": "DuSable Museum",             "category": "culture", "lat": 41.7893,       "lon": -87.6082},
]

# ── coordinate helpers ────────────────────────────────────────────────────────

def meters_to_latlon(x, z, meta, x_min, x_max, z_min, z_max):
    """
    Convert 3MF vertex coordinates to WGS-84 lat/lon using a linear
    mapping from the full vertex range to the mesh bounding box.

    In the 3MF export:
      x increases eastward  (x_min → bbox.w, x_max → bbox.e)
      z increases southward (z_min → bbox.n, z_max → bbox.s)
    """
    bbox = meta["bbox"]
    lon = bbox["w"] + (x - x_min) / (x_max - x_min) * (bbox["e"] - bbox["w"])
    lat = bbox["n"] + (z - z_min) / (z_max - z_min) * (bbox["s"] - bbox["n"])
    return lat, lon


def haversine_m(lat1, lon1, lat2, lon2):
    """Great-circle distance in metres."""
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi  = math.radians(lat2 - lat1)
    dlam  = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.asin(math.sqrt(a))


# ── Union-Find (path-compressed, union-by-rank) ───────────────────────────────

class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank   = [0] * n

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # path halving
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print(f"Loading {INPUT_PATH} …", flush=True)
    with open(INPUT_PATH) as f:
        data = json.load(f)

    meta      = data["meta"]
    mesh      = data["buildings"][0]
    vertices  = mesh["vertices"]   # list of [x, y, z]
    triangles = mesh["triangles"]  # list of [i, j, k]
    n_verts   = len(vertices)
    n_tris    = len(triangles)
    print(f"  {n_verts:,} vertices, {n_tris:,} triangles  ({time.time()-t0:.1f}s)", flush=True)

    # Pre-compute vertex coordinate ranges for lat/lon conversion
    x_min = min(v[0] for v in vertices)
    x_max = max(v[0] for v in vertices)
    z_min = min(v[2] for v in vertices)
    z_max = max(v[2] for v in vertices)

    # ── Step 1: build vertex → triangle adjacency via Union-Find on triangles
    # Two triangles are in the same component if they share at least one vertex.
    # We union each triangle's three vertices, then group triangles by the root
    # of their first vertex.
    print("Building connected components …", flush=True)
    uf = UnionFind(n_verts)

    for tri in triangles:
        a, b, c = tri[0], tri[1], tri[2]
        uf.union(a, b)
        uf.union(b, c)

    print(f"  Union-Find done  ({time.time()-t0:.1f}s)", flush=True)

    # ── Step 2: group triangles by component root
    comp_tris = defaultdict(list)
    for idx, tri in enumerate(triangles):
        root = uf.find(tri[0])
        comp_tris[root].append(idx)

    print(f"  {len(comp_tris):,} raw components found  ({time.time()-t0:.1f}s)", flush=True)

    # ── Step 3: filter noise, remap vertices, compute centroids
    buildings_out = []
    skipped = 0

    # Sort components largest-first for stable ordering
    sorted_comps = sorted(comp_tris.items(), key=lambda kv: -len(kv[1]))

    for comp_idx, (root, tri_indices) in enumerate(sorted_comps):
        if len(tri_indices) < MIN_TRIANGLES:
            skipped += 1
            continue

        # Collect unique vertex indices used by this component
        used_verts = set()
        for ti in tri_indices:
            used_verts.update(triangles[ti])
        used_verts = sorted(used_verts)

        # Build local vertex list and remap table
        remap = {old: new for new, old in enumerate(used_verts)}
        local_verts = [vertices[v] for v in used_verts]
        local_tris  = [[remap[triangles[ti][0]],
                        remap[triangles[ti][1]],
                        remap[triangles[ti][2]]] for ti in tri_indices]

        # Centroid in local metres (average of vertex positions)
        xs = [v[0] for v in local_verts]
        zs = [v[2] for v in local_verts]
        cx = sum(xs) / len(xs)
        cz = sum(zs) / len(zs)
        c_lat, c_lon = meters_to_latlon(cx, cz, meta, x_min, x_max, z_min, z_max)

        buildings_out.append({
            "id":             f"building_{comp_idx:04d}",
            "centroid_lat":   round(c_lat, 7),
            "centroid_lon":   round(c_lon, 7),
            "matched_name":   "unknown",
            "matched_category": "unknown",
            "vertex_count":   len(local_verts),
            "triangle_count": len(local_tris),
            "vertices":       local_verts,
            "triangles":      local_tris,
        })

    print(f"  {len(buildings_out):,} islands kept, {skipped:,} noise islands skipped  ({time.time()-t0:.1f}s)", flush=True)

    # ── Step 4: match islands to known buildings by centroid proximity
    print("Matching to known buildings …", flush=True)
    matched_count = 0
    # Track which known buildings have already been claimed (greedy nearest)
    claimed = {}   # known_name -> (distance, island_idx)

    for i, bld in enumerate(buildings_out):
        best_dist = MATCH_RADIUS_M + 1
        best_known = None
        for kb in KNOWN_BUILDINGS:
            d = haversine_m(bld["centroid_lat"], bld["centroid_lon"],
                            kb["lat"], kb["lon"])
            if d < best_dist:
                best_dist = d
                best_known = kb

        if best_known is not None:
            name = best_known["name"]
            # Only claim if this island is closer than any previous claimant
            if name not in claimed or best_dist < claimed[name][0]:
                # Un-claim previous winner if any
                if name in claimed:
                    prev_idx = claimed[name][1]
                    buildings_out[prev_idx]["matched_name"]     = "unknown"
                    buildings_out[prev_idx]["matched_category"] = "unknown"
                claimed[name] = (best_dist, i)
                bld["matched_name"]     = name
                bld["matched_category"] = best_known["category"]
                matched_count += 1

    print(f"  {matched_count} islands matched to known buildings  ({time.time()-t0:.1f}s)", flush=True)

    # ── Step 5: write output
    output = {
        "meta":      meta,
        "buildings": buildings_out,
    }

    print(f"Writing {OUTPUT_PATH} …", flush=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, separators=(",", ":"))

    size_mb = len(json.dumps(output, separators=(",", ":"))) / 1e6
    print(f"Done. {len(buildings_out)} buildings written ({size_mb:.1f} MB)  total {time.time()-t0:.1f}s")

    # ── Summary table
    print("\n── Matched buildings ──────────────────────────────────────────")
    matched = [b for b in buildings_out if b["matched_name"] != "unknown"]
    matched.sort(key=lambda b: b["matched_name"])
    for b in matched:
        print(f"  {b['matched_name']:<40s}  tris={b['triangle_count']:>7,}  "
              f"lat={b['centroid_lat']:.5f}  lon={b['centroid_lon']:.5f}")

    print(f"\n── Top 10 unmatched (by triangle count) ───────────────────────")
    unmatched = [b for b in buildings_out if b["matched_name"] == "unknown"]
    unmatched.sort(key=lambda b: -b["triangle_count"])
    for b in unmatched[:10]:
        print(f"  {b['id']}  tris={b['triangle_count']:>7,}  "
              f"lat={b['centroid_lat']:.5f}  lon={b['centroid_lon']:.5f}")


if __name__ == "__main__":
    main()
