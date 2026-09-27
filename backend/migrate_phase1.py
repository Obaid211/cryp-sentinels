import sqlite3

conn = sqlite3.connect('ecdat.db')
c = conn.cursor()

# Get existing columns
c.execute('PRAGMA table_info(crypto_assets)')
cols = [row[1] for row in c.fetchall()]
print('Existing columns:', cols)

# Add new Phase 1 columns if they don't exist
new_cols = [
    ('source', 'VARCHAR(50) DEFAULT tls NOT NULL'),
    ('business_criticality', 'VARCHAR(20) DEFAULT medium'),
    ('data_lifetime', 'VARCHAR(20) DEFAULT "1-3y"'),
    ('pqc_recommendation', 'TEXT'),
    ('algorithm', 'VARCHAR(255)'),
    ('usage_context', 'VARCHAR(100)'),
    ('confidence_score', 'FLOAT'),
    ('library', 'VARCHAR(255)'),
    ('file_path', 'TEXT'),
    ('line_number', 'INTEGER'),
]

for col_name, col_def in new_cols:
    if col_name not in cols:
        sql = f'ALTER TABLE crypto_assets ADD COLUMN {col_name} {col_def}'
        print(f'Adding column: {col_name}')
        c.execute(sql)
    else:
        print(f'Column already exists: {col_name}')

conn.commit()
conn.close()
print('Done!')
