from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# 1. Source code scanner
r = client.post('/api/phase1/scan/source-code', json={
    'content': 'import hashlib\npwd = hashlib.md5(b"test").hexdigest()',
    'filename': 'test.py',
    'import_to_inventory': False
})
print('Source scan status:', r.status_code)
data = r.json()
print('Findings:', data['findings_count'])
if data['findings']:
    print('First finding algo:', data['findings'][0]['algorithm'])

# 2. Dependency scanner
r2 = client.post('/api/phase1/scan/dependency', json={
    'content': 'cryptography==41.0.3\npyopenssl>=22.0',
    'filename': 'requirements.txt',
    'import_to_inventory': False
})
print('Dep scan status:', r2.status_code)
d2 = r2.json()
print('Dep findings:', d2['findings_count'])

# 3. PQC recommendation
r3 = client.post('/api/phase1/recommend', json={
    'algorithm': 'ECDSA-P-256',
    'usage_context': 'digital_signature'
})
print('PQC status:', r3.status_code)
d3 = r3.json()
print('PQC recommendation:', d3['recommendation'])

# 4. Inventory still works
r4 = client.get('/api/inventory')
print('Inventory status:', r4.status_code, 'assets:', len(r4.json()))

# 5. Backfill
r5 = client.post('/api/phase1/backfill-recommendations')
print('Backfill status:', r5.status_code, r5.json())
