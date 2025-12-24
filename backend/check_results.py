import sqlite3
import json

def check_db_results():
    for db_file in ['matrix.db', 'cybermatrix.db', 'C:/Users/khanj/Matrix/matrix.db']:
        print(f"\n--- Checking {db_file} ---")
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Get latest scan
            cursor.execute("SELECT id, target_url, status, progress FROM scans ORDER BY created_at DESC LIMIT 1")
            scan = cursor.fetchone()
    
            if not scan:
                print(f"No scans found in {db_file}.")
                conn.close()
                continue
                
            scan_id, target, status, progress = scan
            print(f"Latest Scan: ID={scan_id}, Target={target}, Status={status}, Progress={progress}%")
            
            # Get vulnerabilities for this scan
            cursor.execute("""
                SELECT title, severity, likelihood, impact, exploitability_rationale, cwe_id, owasp_category 
                FROM vulnerabilities 
                WHERE scan_id = ?
            """, (scan_id,))
            
            vulns = cursor.fetchall()
            print(f"Found {len(vulns)} vulnerabilities.")
            
            for v in vulns:
                title, sev, lik, imp, rat, cwe, owasp = v
                print(f"\n[-] {title} ({sev})")
                print(f"    Likelihood: {lik} / 10.0")
                print(f"    Impact: {imp} / 10.0")
                print(f"    CWE: {cwe} | OWASP: {owasp}")
                print(f"    Rationale: {rat}")

            conn.close()
        except Exception as e:
            print(f"Error checking {db_file}: {e}")

if __name__ == "__main__":
    check_db_results()
