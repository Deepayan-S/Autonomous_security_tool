import sqlite3
import json
conn = sqlite3.connect('ahvf_state.db')
conn.row_factory = sqlite3.Row
count = conn.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0]
print(f"Endpoints in DB: {count}")
if count > 0:
    first_url = conn.execute('SELECT url FROM endpoints LIMIT 1').fetchone()[0]
    print(f"URL of first endpoint: {first_url}")
    
count_passive = conn.execute('SELECT COUNT(*) FROM passive_findings').fetchone()[0]
print(f"Passive findings in DB: {count_passive}")
