import sqlite3
import json

def get_final_results():
    db_file = 'matrix.db'
    with open('verified_results.txt', 'w') as f:
        f.write(f"\n--- Checking {db_file} ---\n")
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check latest vulnerabilities
            cursor.execute("""
                SELECT title, severity, likelihood, impact, exploitability_rationale, cwe_id, detected_at
                FROM vulnerabilities 
                ORDER BY id DESC LIMIT 20
            """)
            
            vulns = cursor.fetchall()
            if not vulns:
                f.write(f"No vulnerabilities found in {db_file}.\n")
            else:
                f.write(f"Top {len(vulns)} latest vulnerabilities in {db_file}:\n")
                for v in vulns:
                    title, sev, lik, imp, rat, cwe, dt = v
                    f.write(f"\n[-] {title} ({sev}) | Detected At: {dt}\n")
                    f.write(f"    Likelihood: {lik} | Impact: {imp} | CWE: {cwe}\n")
                    f.write(f"    Rationale: {rat}\n")

            conn.close()
        except Exception as e:
            f.write(f"Error checking {db_file}: {e}\n")
    print(f"Results from {db_file} written to verified_results.txt")




if __name__ == "__main__":
    get_final_results()
