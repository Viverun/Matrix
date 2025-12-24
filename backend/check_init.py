import asyncio
import sqlite3
import os
from core.database import init_db, engine
from config import get_settings

async def test_init():
    settings = get_settings()
    print(f"Testing with DB URL: {settings.database_url}")
    
    # Initialize
    await init_db()
    
    # Check what files were created/modified in the current dir
    files = [f for f in os.listdir('.') if f.endswith('.db')]
    print(f"DB files in current dir: {files}")
    
    for db_file in files:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"Tables in {db_file}: {tables}")
        conn.close()

if __name__ == "__main__":
    asyncio.run(test_init())
