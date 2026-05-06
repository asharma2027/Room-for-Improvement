import zipfile
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'map_mesh.3mf'

with zipfile.ZipFile(path, 'r') as z:
    print('=== All files in ZIP ===')
    for name in z.namelist():
        print(' ', name, '(%d bytes)' % z.getinfo(name).file_size)

    # Read every non-geometry metadata file
    for name in z.namelist():
        if name.endswith('.model') and 'Objects' in name:
            continue  # skip the big geometry file
        if name.startswith('_rels') or name == '[Content_Types].xml':
            continue
        print('\n=== ' + name + ' ===')
        with z.open(name) as f:
            print(f.read().decode('utf-8', errors='replace'))
