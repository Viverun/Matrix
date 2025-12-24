import sqlite3

def migrate_db(db_file):
    print(f"Migrating {db_file}...")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    columns_to_add = [
        ("likelihood", "FLOAT DEFAULT 0.0"),
        ("impact", "FLOAT DEFAULT 0.0"),
        ("exploitability_rationale", "TEXT")
    ]
    
    for col_name, col_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}")
            print(f"Added column {col_name} to vulnerabilities table.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print(f"Column {col_name} already exists.")
            else:
                print(f"Error adding {col_name}: {e}")
                
    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    for db in ['matrix.db', 'cybermatrix.db']:
        try:
            migrate_db(db)
        except Exception as e:
            print(f"Failed to migrate {db}: {e}")
