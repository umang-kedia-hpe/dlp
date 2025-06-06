import os
from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI()

class DataModel(BaseModel):
    data: str

@app.get("/")
async def root():
    return {"message": "Welcome to the FastAPI app!"}

@app.post("/process")
async def process(data: DataModel):
    # Simulate processing the incoming data
    return {"message": "Processed", "data": data.data}

@app.post("/external")
async def external(data: DataModel):
    # Make a direct HTTP request; iptables+mitmproxy will intercept transparently
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        resp = await client.post("https://httpbingo.org/post", json={"data": data.data})
        if resp.status_code == 403:
            return {"error": "Blocked by DLP", "details": resp.text}
        return {"external_response": resp.json()}