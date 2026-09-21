from app.main import create_app

app = create_app()

@app.get("/")
async def root():
    return {"message": "Agentic Firewall is running"}

