import os
import psycopg2
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

database_url = os.getenv("DATABASE_URL")
print("LOADED URL:", database_url)

try:
    if not database_url:
        raise ValueError("DATABASE_URL is missing from the .env file!")

    # Connect to Supabase PostgreSQL using environment variables
    connection = psycopg2.connect(database_url)
    cursor = connection.cursor()
    print("SUCCESS: Connected to Supabase database!")

    # Insert a test firewall log
    insert_query = """
        INSERT INTO firewall_logs (event_type, status, details, source_ip)
        VALUES (%s, %s, %s, %s);
    """
    cursor.execute(insert_query, ("TEST_EVENT", "ALLOWED", "Environment variable test log", "127.0.0.1"))
    
    # Commit the transaction
    connection.commit()
    print("SUCCESS: Test log written to Supabase table using .env!")

    # Close the connection
    cursor.close()
    connection.close()

except Exception as error:
    print(f"ERROR: Connection failed -> {error}")