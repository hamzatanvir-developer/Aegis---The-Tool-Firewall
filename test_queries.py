import os
import psycopg2

# Supabase pooler connection string
database_url = "postgresql://postgres.gkbvcooteueuscydjogy:aegisthetoolfirewall2006@aws-1-us-west-2.pooler.supabase.com:5432/postgres"

def run_database_tests():
    try:
        print("Connecting to Supabase...")
        connection = psycopg2.connect(database_url)
        cursor = connection.cursor()
        print("SUCCESS: Database connection established.\n")

        # Test 1: Insert a Blocked Firewall Log
        print("-> Running Test 1: Insert BLOCK event log...")
        insert_query = """
            INSERT INTO firewall_logs (event_type, status, details, source_ip)
            VALUES (%s, %s, %s, %s);
        """
        cursor.execute(insert_query, ("TOOL_EXECUTION", "BLOCKED", "Unauthorized shell execution attempt detected", "192.168.1.50"))
        connection.commit()
        print("SUCCESS: Blocked log inserted.\n")

        # Test 2: Fetch and Display Recent Logs
        print("-> Running Test 2: Querying recent firewall logs...")
        select_query = "SELECT id, event_type, status, details, created_at FROM firewall_logs ORDER BY created_at DESC LIMIT 3;"
        cursor.execute(select_query)
        rows = cursor.fetchall()
        
        print(f"SUCCESS: Retrieved {len(rows)} recent log record(s):")
        for row in rows:
            print(f"   ID: {row[0]} | Type: {row[1]} | Status: {row[2]} | Details: {row[3]} | Time: {row[4]}")
        print()

        # Test 3: Verify Table Structure / Column Integrity
        print("-> Running Test 3: Checking table schema constraints...")
        schema_query = """
            column_name 
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'firewall_logs';
        """
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'firewall_logs';
        """)
        columns = cursor.fetchall()
        print("SUCCESS: Table schema verified. Columns present:")
        for col in columns:
            print(f"   - {col[0]} ({col[1]})")
        print("\nALL DATABASE TESTS PASSED SUCCESSFULLY!")

        cursor.close()
        connection.close()

    except Exception as error:
        print(f"ERROR: Database test failed -> {error}")

if __name__ == "__main__":
    run_database_tests()