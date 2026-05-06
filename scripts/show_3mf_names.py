import json
with open('public/data/3mf_extract.json') as f:
    data = json.load(f)
others = data['other']
print('Total other objects:', len(others))
for i, o in enumerate(others):
    name = o['name']
    osm_id = o['osm_id']
    verts = len(o['vertices'])
    tris = len(o['triangles'])
    print('[' + str(i) + '] name=' + repr(name) + '  osm_id=' + repr(osm_id) + '  verts=' + str(verts) + '  tris=' + str(tris))
