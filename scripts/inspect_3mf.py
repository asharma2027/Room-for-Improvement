#!/usr/bin/env python3
"""
inspect_3mf.py  —  Diagnostic tool to see what's actually inside a .3mf file.

Usage:
    python3 scripts/inspect_3mf.py path/to/your-file.3mf
"""

import sys
import os
import zipfile
import xml.etree.ElementTree as ET

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/inspect_3mf.py <path-to-file.3mf>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    print(f"=== ZIP contents of {os.path.basename(path)} ===")
    with zipfile.ZipFile(path, 'r') as z:
        for name in z.namelist():
            info = z.getinfo(name)
            print(f"  {name}  ({info.file_size:,} bytes)")

        # Find the model file
        model_candidates = [n for n in z.namelist() if n.endswith('.model')]
        if not model_candidates:
            print("\nERROR: No .model file found in ZIP")
            return

        model_path = '3D/3dmodel.model' if '3D/3dmodel.model' in z.namelist() else model_candidates[0]
        print(f"\n=== Parsing {model_path} ===")

        with z.open(model_path) as f:
            content = f.read()

        # Show first 3000 chars of raw XML so we can see the structure
        print("\n--- First 3000 chars of raw XML ---")
        print(content[:3000].decode('utf-8', errors='replace'))
        print("\n--- (truncated) ---")

        # Parse and inspect
        root = ET.fromstring(content)
        print(f"\n=== XML root tag: {root.tag} ===")
        print(f"Root attributes: {root.attrib}")

        print("\n=== All unique tags in the document ===")
        tags = set()
        def collect_tags(elem):
            tags.add(elem.tag)
            for child in elem:
                collect_tags(child)
        collect_tags(root)
        for t in sorted(tags):
            print(f"  {t}")

        print("\n=== Direct children of root ===")
        for child in root:
            print(f"  <{child.tag}> — {len(list(child))} children, attribs: {dict(list(child.attrib.items())[:5])}")

        # Try to find resources/objects regardless of namespace
        print("\n=== Searching for 'object' elements (any namespace) ===")
        all_objects = root.findall('.//{*}object') or root.findall('.//object')
        print(f"  Found {len(all_objects)} object elements")
        for i, obj in enumerate(all_objects[:10]):
            print(f"  [{i}] tag={obj.tag}  attribs={dict(list(obj.attrib.items())[:8])}")

        print("\n=== Searching for 'mesh' elements (any namespace) ===")
        all_meshes = root.findall('.//{*}mesh') or root.findall('.//mesh')
        print(f"  Found {len(all_meshes)} mesh elements")
        for i, m in enumerate(all_meshes[:5]):
            verts = m.findall('.//{*}vertex') or m.findall('.//vertex')
            tris  = m.findall('.//{*}triangle') or m.findall('.//triangle')
            print(f"  [{i}] vertices={len(verts)}, triangles={len(tris)}")

        print("\n=== Searching for 'component' elements ===")
        components = root.findall('.//{*}component') or root.findall('.//component')
        print(f"  Found {len(components)} component elements")
        for i, c in enumerate(components[:5]):
            print(f"  [{i}] attribs={dict(list(c.attrib.items())[:8])}")

        print("\n=== Metadata elements ===")
        metas = root.findall('.//{*}metadata') or root.findall('.//metadata')
        for m in metas[:20]:
            print(f"  name={m.get('name','?')}  value={m.text or m.get('value','')}")

if __name__ == '__main__':
    main()
