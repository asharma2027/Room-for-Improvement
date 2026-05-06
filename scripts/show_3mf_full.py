import json
with open('public/data/3mf_extract.json') as f:
    data = json.load(f)

for key in ('buildings', 'roads', 'other'):
    items = data[key]
    print('=== ' + key + ' (' + str(len(items)) + ') ===')
    for o in items:
        print('  id=' + o['osm_id'] + '  name=' + repr(o['name']) + '  cat=' + o.get('category','?') + '  verts=' + str(len(o['vertices'])) + '  tris=' + str(len(o['triangles'])))
