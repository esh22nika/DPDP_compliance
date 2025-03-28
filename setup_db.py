import sqlite3

def create_tables():
    conn = sqlite3.connect("security_scans.db")
    cursor = conn.cursor()

    # Drop old table if exists (ONLY do this if you don't mind losing existing data)
    cursor.execute("DROP TABLE IF EXISTS scans")

    # Create a new table with 'username' column
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            website_url TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_tables()
    print("Database setup complete!")
