import sqlite3
import pandas as pd
import json

def inspect_database(db_path="backend/users.db"):
    """Displays tables and data from the SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        # Get list of tables
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        print(f"\n{'='*50}")
        print(f"DATABASE: {db_path}")
        print(f"TABLES: {', '.join(tables)}")
        print(f"{'='*50}\n")
        
        for table in tables:
            print(f"--- TABLE: {table} ---")
            try:
                # Use pandas for nice formatting
                df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
                
                # Filter out heavy/sensitive data for clean terminal view
                cols_to_drop = ['keystroke_data', 'mouse_data', 'password_hash', 'salt']
                present_cols = [c for c in cols_to_drop if c in df.columns]
                
                if present_cols:
                    display_df = df.drop(columns=present_cols)
                    print(f"(Filtered out: {', '.join(present_cols)})")
                else:
                    display_df = df
                    
                if display_df.empty:
                    print("No data found.")
                else:
                    print(display_df.to_string(index=False))
                    
            except Exception as e:
                print(f"Error reading table {table}: {e}")
            print("\n")
            
        conn.close()
    except Exception as e:
        print(f"Failed to connect to database: {e}")

if __name__ == "__main__":
    inspect_database()
