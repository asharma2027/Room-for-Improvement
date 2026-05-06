#!/usr/bin/env python3
"""
extract_3mf.py  —  Convert a map2model .3mf export to JSON for the campus map.

Usage:
    python3 scripts/extract_3mf.py path/to/your-file.3mf

Output:
    public/data/3mf_extract.json

The JSON contains two top-level arrays:
  "buildings" — list of building meshes, each with:
      { "name": str, "osm_id": str, "vertices": [[x,y,z],...], "triangles": [[a,b,c],...] }
  "roads"     — list of road meshes, each with:
      { "name": str, "type": str, "vertices": [[x,y,z],...], "triangles": [[a,b,c],...] }

All coordinates are in SCENE SPACE (meters), matching the Three.js map's
latLngToXZ() convention:
    origin = (41.7895 lat, -87.5995 lon)
    x = east  (positive = east of origin)
    z = south (positive = south of origin, i.e. -lat direction)
    y = up    (height in meters)

The 3MF coordinate system (from map2model):
    origin = SW corner of the export bounding box
    x = east  (mm)
    y = north (mm)  ← note: map2model uses Y for north, Z for height
    z = up    (mm)

So the conversion is:
    scene_x =  (3mf_x / 1000) * METERS_PER_MM_X  + offset_x
    scene_z = -(3mf_y / 1000) * METERS_PER_MM_Y  + offset_z
    scene_y =  (3mf_z / 1000)   (height, kept as-is but scaled)
"""

import sys
import os
import json
import zipfile
import xml.etree.ElementTree as ET
import math

# ── map2model export settings (from your generatorOptions JSON) ──────────────
MAP_WIDTH_MM   = 150.0          # mapWidthMM
BASE_LAYER_MM  = 1.0            # baseLayerMM (ground plane offset)

# Export bounding box (from areaPolygon)
BBOX_W = -87.611761   # west  lon
BBOX_E = -87.58687    # east  lon
BBOX_S =  41.784177   # south lat
BBOX_N =  41.802735   # north lat

# ── Three.js scene origin (must match explore.ejs) ───────────────────────────
ORIGIN_LAT =  41.7895
ORIGIN_LNG = -87.5995

# ── Derived scale factors ─────────────────────────────────────────────────────
# Geographic extents of the export area
DELTA_LON = BBOX_E - BBOX_W   # degrees longitude
DELTA_LAT = BBOX_N - BBOX_S   # degrees latitude

# Approximate meters per degree at this latitude
LAT_RAD = math.radians((BBOX_N + BBOX_S) / 2)
METERS_PER_DEG_LAT = 111320.0
METERS_PER_DEG_LON = 111320.0 * math.cos(LAT_RAD)

# Real-world size of the export area in meters
AREA_WIDTH_M  = DELTA_LON * METERS_PER_DEG_LON   # east-west
AREA_HEIGHT_M = DELTA_LAT * METERS_PER_DEG_LAT   # north-south

# Scale: how many real meters does 1mm in the 3MF represent?
SCALE_X = AREA_WIDTH_M  / MAP_WIDTH_MM   # m/mm east-west
# map2model keeps aspect ratio, so height of the model in mm:
MAP_HEIGHT_MM = MAP_WIDTH_MM * (AREA_HEIGHT_M / AREA_WIDTH_M)
SCALE_Y = AREA_HEIGHT_M / MAP_HEIGHT_MM  # m/mm north-south

# Scene offset: SW corner of bbox in scene coordinates
# scene_x of SW corner:
SW_SCENE_X = (BBOX_W - ORIGIN_LNG) * METERS_PER_DEG_LON
# scene_z of SW corner (z is positive southward, so south lat → larger z):
SW_SCENE_Z = -(BBOX_S - ORIGIN_LAT) * METERS_PER_DEG_LAT

print(f"Export area: {AREA_WIDTH_M:.1f}m × {AREA_HEIGHT_M:.1f}m")
print(f"Scale: {SCALE_X:.4f} m/mm (X),  {SCALE_Y:.4f} m/mm (Y)")
print(f"SW corner in scene: x={SW_SCENE_X:.2f}, z={SW_SCENE_Z:.2f}")


def mm_to_scene(x_mm, y_mm, z_mm):
    """Convert 3MF (x=east, y=north, z=up) in mm → Three.js scene coords in m."""
    scene_x = SW_SCENE_X + (x_mm * SCALE_X)
    scene_z = SW_SCENE_Z - (y_mm * SCALE_Y)   # north → negative z
    scene_y = z_mm / 1000.0                    # mm → m, y=up stays y
    return [round(scene_x, 4), round(scene_y, 4), round(scene_z, 4)]


# ── 3MF namespace ─────────────────────────────────────────────────────────────
NS = {
    '3mf':  'http://schemas.microsoft.com/3dmanufacturing/core/2015/02',
    'p':    'http://schemas.microsoft.com/3dmanufacturing/production/2015/06',
}

def parse_3mf(path):
    """
    Open the .3mf ZIP and return a dict of { zip_path: xml_root } for every
    .model file found.  map2model splits geometry into external part files
    (e.g. 3D/Objects/object-1.model) referenced via <component p:path=...>.
    We parse all of them so the extractor can find meshes wherever they live.

    NOTE: Part files can be very large (100MB+). We use iterparse for those
    to avoid loading the entire XML tree into memory at once.
    """
    roots = {}
    with zipfile.ZipFile(path, 'r') as z:
        model_files = [n for n in z.namelist() if n.endswith('.model')]
        if not model_files:
            raise FileNotFoundError("No .model file found inside the 3MF ZIP")
        for model_path in model_files:
            size = z.getinfo(model_path).file_size
            print(f"Reading model from: {model_path}  ({size:,} bytes)")
            with z.open(model_path) as f:
                roots[model_path] = ET.parse(f).getroot()
    return roots


def extract_all_objects_streaming(zip_path, part_file_path):
    """
    Stream-parse a large part .model file using iterparse so we never hold
    the full tree in memory.  Returns list of (obj_id, obj_name, vertices, triangles).
    Each <object> element is fully parsed then discarded.
    """
    NS_CORE = 'http://schemas.microsoft.com/3dmanufacturing/core/2015/02'
    TAG_OBJ  = f'{{{NS_CORE}}}object'
    TAG_VERT = f'{{{NS_CORE}}}vertex'
    TAG_TRI  = f'{{{NS_CORE}}}triangle'

    results = []
    current_obj = None
    current_verts = []
    current_tris  = []
    in_vertices   = False
    in_triangles  = False
    obj_count     = 0

    print(f"  Streaming {part_file_path} ...")

    with zipfile.ZipFile(zip_path, 'r') as z:
        with z.open(part_file_path) as f:
            for event, elem in ET.iterparse(f, events=('start', 'end')):
                tag = elem.tag

                if event == 'start':
                    if tag == TAG_OBJ:
                        current_obj   = elem.attrib
                        current_verts = []
                        current_tris  = []
                    elif tag.endswith('}vertices') or tag == 'vertices':
                        in_vertices = True
                    elif tag.endswith('}triangles') or tag == 'triangles':
                        in_triangles = True
                    elif in_vertices and (tag == TAG_VERT or tag == 'vertex'):
                        x = float(elem.get('x', 0))
                        y = float(elem.get('y', 0))
                        z_val = float(elem.get('z', 0))
                        current_verts.append(mm_to_scene(x, y, z_val))
                    elif in_triangles and (tag == TAG_TRI or tag == 'triangle'):
                        current_tris.append([
                            int(elem.get('v1')),
                            int(elem.get('v2')),
                            int(elem.get('v3')),
                        ])

                elif event == 'end':
                    if tag.endswith('}vertices') or tag == 'vertices':
                        in_vertices = False
                    elif tag.endswith('}triangles') or tag == 'triangles':
                        in_triangles = False
                    elif tag == TAG_OBJ:
                        if current_obj is not None and current_verts:
                            obj_id   = current_obj.get('id', '')
                            obj_name = current_obj.get('name', '') or f'object_{obj_id}'
                            results.append((obj_id, obj_name, current_verts, current_tris))
                            obj_count += 1
                            if obj_count % 100 == 0:
                                print(f"    ... {obj_count} objects parsed so far")
                        # Free memory
                        elem.clear()
                        current_obj   = None
                        current_verts = []
                        current_tris  = []

    print(f"  Done — {len(results)} objects extracted from {part_file_path}")
    return results


def extract_mesh(object_elem):
    """
    Given a <object> element, return (vertices, triangles) in scene coords.
    vertices  = [[sx, sy, sz], ...]
    triangles = [[i, j, k], ...]
    """
    # Try both namespaced and plain tags
    mesh_elem = object_elem.find('3mf:mesh', NS) or object_elem.find('mesh')
    if mesh_elem is None:
        return [], []

    verts_elem = mesh_elem.find('3mf:vertices', NS) or mesh_elem.find('vertices')
    tris_elem  = mesh_elem.find('3mf:triangles', NS) or mesh_elem.find('triangles')
    if verts_elem is None or tris_elem is None:
        return [], []

    vertices = []
    for v in (verts_elem.findall('3mf:vertex', NS) or verts_elem.findall('vertex')):
        x = float(v.get('x', 0))
        y = float(v.get('y', 0))
        z = float(v.get('z', 0))
        vertices.append(mm_to_scene(x, y, z))

    triangles = []
    for t in (tris_elem.findall('3mf:triangle', NS) or tris_elem.findall('triangle')):
        triangles.append([int(t.get('v1')), int(t.get('v2')), int(t.get('v3'))])

    return vertices, triangles


def classify_object(name, color):
    """
    map2model names objects like:
        "building"  or  "building_<osmid>"
        "highway"   or  "highway_residential_<osmid>"
        "landuse"   or  "landuse_grass_<osmid>"
        "waterway"  etc.
    Color fallback uses the generatorOptions defaults:
        buildings: #b8b8b8
        roads:     #262626
        greenery:  #18a848
        water:     #3399ff
    """
    n = (name or '').lower()

    # Name-based classification (most reliable for map2model)
    if n.startswith('building'):
        return 'building'
    if n.startswith('highway') or n.startswith('road') or n.startswith('path') \
            or n.startswith('footway') or n.startswith('cycleway') \
            or n.startswith('pedestrian') or n.startswith('service'):
        return 'road'
    if n.startswith('landuse') or n.startswith('landcover') or n.startswith('natural'):
        return 'greenery'
    if n.startswith('water') or n.startswith('river') or n.startswith('stream'):
        return 'water'

    # Color fallback
    if color:
        c = color.lower().strip().lstrip('#')
        if c in ('b8b8b8',):
            return 'building'
        if c in ('262626',):
            return 'road'
        if c in ('18a848',):
            return 'greenery'
        if c in ('3399ff',):
            return 'water'

    return 'other'


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/extract_3mf.py <path-to-file.3mf>")
        sys.exit(1)

    input_path = sys.argv[1]
    if not os.path.exists(input_path):
        print(f"File not found: {input_path}")
        sys.exit(1)

    print(f"\nParsing {input_path} ...")

    # ── Step 1: Read extruder→color mapping from project_settings.config ────
    # filament_colour array is 0-indexed; extruder values in config are 1-indexed.
    extruder_colors = {}   # extruder_number (int) → hex color string
    with zipfile.ZipFile(input_path, 'r') as z:
        if 'Metadata/project_settings.config' in z.namelist():
            with z.open('Metadata/project_settings.config') as f:
                proj = json.loads(f.read().decode('utf-8'))
            colors = proj.get('filament_colour', [])
            for i, c in enumerate(colors):
                extruder_colors[i + 1] = c.lower().strip('#')
            print("Extruder color map:", extruder_colors)

    # ── Step 2: Read part→extruder mapping from model_settings.config ────────
    part_extruder = {}   # part_id (str) → extruder_number (int)
    with zipfile.ZipFile(input_path, 'r') as z:
        if 'Metadata/model_settings.config' in z.namelist():
            with z.open('Metadata/model_settings.config') as f:
                cfg_root = ET.parse(f).getroot()
            for obj_elem in cfg_root.findall('.//object'):
                for part_elem in obj_elem.findall('part'):
                    part_id = part_elem.get('id', '')
                    for meta in part_elem.findall('metadata'):
                        if meta.get('key') == 'extruder':
                            part_extruder[part_id] = int(meta.get('value', 1))
            print("Part→extruder map:", part_extruder)

    # ── Step 3: Build part_id→category from the two maps ─────────────────────
    # Color→category (from generatorOptions):
    #   3399ff = water, 18a848 = greenery, b8b8b8 = buildings,
    #   262626 = roads,  ffffff = frame/base
    COLOR_CATEGORY = {
        '3399ff': 'water',
        '18a848': 'greenery',
        'b8b8b8': 'building',
        '262626': 'road',
        'ffffff': 'frame',
    }
    part_category = {}
    for part_id, extruder_num in part_extruder.items():
        color = extruder_colors.get(extruder_num, '')
        part_category[part_id] = COLOR_CATEGORY.get(color, 'other')
    print("Part→category map:", part_category)

    # ── Step 4: Stream the geometry part file ─────────────────────────────────
    with zipfile.ZipFile(input_path, 'r') as z:
        all_model_files = [n for n in z.namelist() if n.endswith('.model')]
    part_files = [f for f in all_model_files if f != '3D/3dmodel.model']
    if not part_files:
        part_files = all_model_files

    buildings = []
    roads     = []
    others    = []

    for part_path in part_files:
        raw_objects = extract_all_objects_streaming(input_path, part_path)
        for obj_id, obj_name, vertices, triangles in raw_objects:
            category = part_category.get(obj_id, 'other')
            entry = {
                'name':      obj_name,
                'osm_id':    obj_id,
                'category':  category,
                'vertices':  vertices,
                'triangles': triangles,
            }
            if category == 'building':
                buildings.append(entry)
            elif category == 'road':
                roads.append(entry)
            else:
                others.append(entry)

    print(f"\nExtracted:")
    print(f"  Buildings : {len(buildings)}")
    print(f"  Roads     : {len(roads)}")
    print(f"  Other     : {len(others)}")

    output = {
        'meta': {
            'source':       os.path.basename(input_path),
            'bbox':         {'w': BBOX_W, 'e': BBOX_E, 's': BBOX_S, 'n': BBOX_N},
            'origin':       {'lat': ORIGIN_LAT, 'lng': ORIGIN_LNG},
            'scale_x_mpm':  SCALE_X,
            'scale_y_mpm':  SCALE_Y,
        },
        'buildings': buildings,
        'roads':     roads,
        'other':     others,
    }

    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'public', 'data', '3mf_extract.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, 'w') as f:
        json.dump(output, f, separators=(',', ':'))  # compact — no pretty print, file can be large

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"\nWrote {out_path}  ({size_mb:.2f} MB)")
    print("\nNext step: share the output JSON with Kiro to integrate into the map.")


if __name__ == '__main__':
    main()
