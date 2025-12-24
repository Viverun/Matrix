import sqlite3

def inspect_vuln():
    conn = sqlite3.connect('matrix.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    row = cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        print(f"Columns: {list(row.keys())}")
        print("Vulnerability Inspection:")
        for key in row.keys():
            print(f"  {key}: {row[key]}")
    else:
        print("No vulnerabilities found.")
    conn.close()

if __name__ == "__main__":
    inspect_vuln()
