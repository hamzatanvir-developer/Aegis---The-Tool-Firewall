import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from aegis.dashboard import router as dashboard_router

# Load environment variables
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI(title="Aegis Tool Firewall API", version="1.0")

# Mount your modular dashboard router
app.include_router(dashboard_router)

class ToolExecutionRequest(BaseModel):
    event_type: str
    status: str
    details: str
    source_ip: str

@app.get("/")
def read_root():
    return {"message": "Aegis Tool Firewall API is running live successfully!"}

@app.post("/log-event")
def log_event(request: ToolExecutionRequest):
    try:
        connection = psycopg2.connect(DATABASE_URL)
        cursor = connection.cursor()
        
        insert_query = """
            INSERT INTO firewall_logs (event_type, status, details, source_ip)
            VALUES (%s, %s, %s, %s);
        """
        cursor.execute(insert_query, (request.event_type, request.status, request.details, request.source_ip))
        connection.commit()
        
        cursor.close()
        connection.close()
        return {"status": "success", "message": "Firewall log saved to Supabase!"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")