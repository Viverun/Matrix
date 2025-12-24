import sqlite3

def list_scans():
    conn = sqlite3.connect('cybermatrix.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, target_url, created_at, status, progress FROM scans ORDER BY id DESC LIMIT 5")
    scans = cursor.fetchall()
    
    print("Latest Scans in cybermatrix.db:")
    for s in scans:
        print(f"ID: {s[0]} | Target: {s[1]} | Date: {s[2]} | Status: {s[3]} | Progress: {s[4]}%")
    conn.close()

if __name__ == "__main__":
    list_scans()
