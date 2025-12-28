import sqlite3

def dump_scans():
    conn = sqlite3.connect('matrix.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, scan_type, status FROM scans WHERE status='PENDING'")
    rows = cursor.fetchall()
    print("Raw Pending Scans:")
    for row in rows:
        print(row)
    conn.close()

if __name__ == "__main__":
    dump_scans()
