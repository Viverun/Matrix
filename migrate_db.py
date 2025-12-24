import sqlite3
import os

db_path = 'backend/matrix.db'

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get existing columns
cursor.execute('PRAGMA table_info(vulnerabilities)')
existing_columns = [row[1] for row in cursor.fetchall()]

new_columns = [
    ('is_suppressed', 'BOOLEAN DEFAULT 0'),
    ('suppression_reason', 'TEXT'),
    ('final_verdict', 'VARCHAR(50)'),
    ('action_required', 'BOOLEAN DEFAULT 1'),
    ('detection_confidence', 'FLOAT DEFAULT 0.0'),
    ('exploit_confidence', 'FLOAT DEFAULT 0.0'),
    ('scope_impact', 'JSON'),
    ('likelihood', 'FLOAT'),
    ('impact', 'FLOAT'),
    ('exploitability_rationale', 'TEXT')
]

for col_name, col_type in new_columns:
    if col_name not in existing_columns:
        print(f"Adding column {col_name}...")
        try:
            cursor.execute(f'ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}')
        except Exception as e:
            print(f"Error adding {col_name}: {e}")
    else:
        print(f"Column {col_name} already exists.")

conn.commit()
conn.close()
print("Migration complete.")
