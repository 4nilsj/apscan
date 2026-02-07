from fastapi import FastAPI, Depends, HTTPException, Header, Body, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Union
import uvicorn
import yaml
import json
import base64

app = FastAPI(title="Vulnerable Mock API", version="1.0.0")

# Vulnerability 1: Unauthenticated Access to sensitive data
@app.get("/users/{user_id}", summary="Get User Details")
def get_user(user_id: int):
    # SIMULATED VULNERABILITY: No auth check
    return {"user_id": user_id, "username": "admin", "email": "admin@example.com", "role": "admin"}

# Protected Endpoint
@app.get("/admin", summary="Admin Panel")
def admin_panel(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"message": "Welcome Admin"}

# Vulnerability 2: SQL Injection (Simulated Error)
@app.get("/products", summary="Search Products")
def search_products(category: str):
    # SIMULATION: If category contains single quote, return fake SQL error
    if "'" in category:
        # Returning a string that matches our SQLi regex
        return "Internal Server Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    return {"products": ["item1", "item2"]}

# Vulnerability 3: Reflected XSS
@app.get("/search", summary="Search Site")
def search_site(q: str):
    # SIMULATION: Reflect input raw (HTML response usually required for XSS but text/plain reflection counts as source, 
    # though our rule checks body content).
    # We return JSON but include the raw tag.
    return {"results": [], "query": q}

# Vulnerability 4: GraphQL Introspection
@app.post("/graphql", summary="GraphQL Endpoint")
async def graphql_endpoint(request: dict):
    query = request.get("query", "")
    if "__schema" in query:
        # Return a fake schema for introspection
        return {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {"name": "getUser", "args": [{"name": "id"}]},
                                {"name": "listProducts", "args": []}
                            ]
                        }
                    ]
                }
            }
        }
    if "query too deep" in query: # Simulation logic would be complex, just mock response
         # Simulate success for depth check 
         pass
    return {"data": {"result": "success"}}

# Vulnerability 5: JWT None Alg
@app.get("/jwt-protected", summary="JWT Protected")
def jwt_protected(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    
    token = authorization.split(" ")[1]
    if "alg\":\"none" in base64.urlsafe_b64decode(token.split('.')[0] + "==").decode():
        return {"message": "Bypassed with None Alg!"}
        
    return {"message": "Authenticated"}

class PingInput(BaseModel):
    cmd: str

@app.post("/api/ping")
def ping(input: PingInput):
    # Vulnerable to CMDi
    if ";" in input.cmd or "|" in input.cmd or "%0A" in input.cmd:
        return PlainTextResponse(f"Pinging... \nroot:x:0:0:root:/root:/bin/bash\nuid=0(root) gid=0(root)")
    if "dir" in input.cmd.lower() or "type" in input.cmd.lower():
         return PlainTextResponse("Volume Serial Number is 1234-5678\nDirectory of C:\\")
    return {"message": "pong"}

class TemplateInput(BaseModel):
    template: str

@app.post("/api/render")
def render_template(input: TemplateInput):
    # Vulnerable to SSTI
    if "{{7*7}}" in input.template or "${7*7}" in input.template:
        return PlainTextResponse("Output: 49")
    if "{{config}}" in input.template:
        return PlainTextResponse("&lt;Config 'flask.app'&gt;")
    return {"message": "rendered"}

class ProductQuery(BaseModel):
    query: Any

@app.post("/api/products")
def get_products(input: ProductQuery):
    # Vulnerable to NoSQLi
    # Simulate error if object passed
    query = input.query
    if isinstance(query, dict):
         if "$ne" in str(query) or "$regex" in str(query) or "$gt" in str(query):
             return PlainTextResponse("MongoError: Expected string, got object", status_code=500)
    return {"products": []}

@app.post("/api/parse_xml")
async def parse_xml(request: Request):
    # Vulnerable to XXE
    ct = request.headers.get("Content-Type", "")
    if "xml" in ct:
        body = await request.body()
        if b"file:///etc/passwd" in body:
            return PlainTextResponse("root:x:0:0:root:/root:/bin/bash")
    return {"message": "parsed"}

@app.post("/api/login")
def login(creds: Dict[str, str]):
    if creds.get("username") == "admin" and creds.get("password") == "password":
        return {"token": "valid_token_123", "message": "Login successful"}
    return JSONResponse(status_code=401, content={"message": "Invalid credentials"})

@app.get("/api/profile")
def profile(id: str = "1", authorization: str = Header(None)):
    if authorization == "Bearer valid_token_123":
        # Authenticated SQLi
        if "'" in id or "OR" in id:
             return PlainTextResponse("SQL Syntax Error: SELECT * FROM users WHERE id = " + id, status_code=500)
        return {"user": "admin", "role": "superuser", "id": id}
    return JSONResponse(status_code=401, content={"message": "Unauthorized"})
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    if b"<?php" in content:
        return PlainTextResponse("File Upload Vulnerability: PHP detected", status_code=200)
    return {"filename": file.filename, "size": len(content)}

# Vulnerability: Open Redirect
@app.get("/redirect")
def redirect_endpoint(url: str):
    return JSONResponse(status_code=302, headers={"Location": url}, content={})

# Vulnerability: Shadow API
@app.get("/old")
def shadow_api():
    return {"message": "This is a deprecated endpoint", "status": "active"}

# Vulnerability: PII Exposure
@app.get("/api/users_pii")
def get_pii_users():
    return {
        "users": [
            {"id": 1, "email": "admin@example.com", "ssn": "123-45-6789"},
            {"id": 2, "email": "user@test.com", "credit_card": "4111 2222 3333 4444"}
        ]
    }

# Vulnerability: Stack Trace
@app.route("/api/stack_trace", methods=["POST"])
async def stack_trace_endpoint(request: Request):
    # Simulate stack trace regardless of input
    return JSONResponse(status_code=500, content={"error": "ISE", "trace": "Traceback (most recent call last): ..."})

# Vulnerability: Unsafe Methods
@app.route("/api/trace_me", methods=["TRACE"]) # FastAPI doesn't easily support TRACE via decorator
def trace_endpoint(request: Request):
    return JSONResponse(content={"method": "TRACE", "headers": dict(request.headers)})
    
# Manual handling for TRACE since FastAPI filters it? 
# Using a middleware or just verifying logic.
# Actually, let's just use @app.api_route
@app.api_route("/api/unsafe", methods=["TRACE", "TRACK"])
async def unsafe_method(request: Request):
    return JSONResponse(content={"echo": "unsafe"})

# Vulnerability: Prototype Pollution
@app.post("/api/pollute")
def pollute_endpoint(data: dict):
    # Reflect full structure
    return data

# Vulnerability: Recon
@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /admin")


# Vulnerability: Secrets Exposure
@app.get("/api/config_secrets")
def get_secrets():
    return {
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA..."
    }

# Vulnerability: Dependency Check (Exposed File)
@app.get("/package.json")
def get_package_json():
    return JSONResponse(
        content={"name": "vulnerable-app", "dependencies": {"express": "4.17.1"}},
        headers={"X-Powered-By": "Express/4.17.1"}
    )

@app.get("/api/protected/bearer")
async def protected_bearer(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    return {"message": "Authenticated with Bearer token", "user": "admin"}

@app.get("/api/protected/cookie")
async def protected_cookie(session_id: str = Cookie(None)):
    if session_id != "xyz123":
        raise HTTPException(status_code=401, detail="Missing or invalid session cookie")
    return {"message": "Authenticated with Cookie", "user": "alice"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
