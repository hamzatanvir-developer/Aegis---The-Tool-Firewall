import os
import psycopg2
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI(title="Aegis Tool Firewall API", version="1.0")

class ToolExecutionRequest(BaseModel):
    event_type: str
    status: str
    details: str
    source_ip: str

@app.get("/")
def read_root():
    return {"message": "Aegis Tool Firewall API is running live successfully!"}

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis - Tool Firewall Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen p-8">
        <div class="max-w-6xl mx-auto">
            <header class="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight text-indigo-400">🛡️ Aegis Tool Firewall</h1>
                    <p class="text-sm text-slate-400 mt-1">Real-time security monitoring & agent protection dashboard</p>
                </div>
                <div class="flex items-center gap-2">
                    <span class="inline-block w-3 h-3 bg-emerald-500 rounded-full animate-pulse"></span>
                    <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">System Live</span>
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                    <h3 class="text-xs font-medium text-slate-400 uppercase tracking-wider">API Status</h3>
                    <p class="text-2xl font-bold text-emerald-400 mt-2">Operational</p>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                    <h3 class="text-xs font-medium text-slate-400 uppercase tracking-wider">Database Connection</h3>
                    <p class="text-2xl font-bold text-indigo-400 mt-2">Supabase Connected</p>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                    <h3 class="text-xs font-medium text-slate-400 uppercase tracking-wider">Protection Engine</h3>
                    <p class="text-2xl font-bold text-sky-400 mt-2">Active</p>
                </div>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                <h2 class="text-xl font-semibold mb-4 text-slate-200">Firewall Overview</h2>
                <p class="text-slate-400 text-sm">Your tool firewall service is up and running successfully. Logs are being captured and processed in real-time.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

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