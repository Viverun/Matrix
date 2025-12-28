
import sqlite3
import json

conn = sqlite3.connect('matrix.db')
cursor = conn.cursor()
cursor.execute("SELECT title, severity, ai_analysis FROM vulnerabilities WHERE scan_id=37 AND title LIKE '%XSS%'")
row = cursor.fetchone()
if row:
    print(f"Title: {row[0]}")
    print(f"Severity: {row[1]}")
    print(f"AI Analysis: {row[2]}")
else:
    print("No XSS found for Scan 36")
conn.close()
