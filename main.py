import os
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest
import google.oauth2.credentials
from pydantic import BaseModel
from typing import Optional
import uuid
import json
import httpx

# Initialize FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],  # Adjust for your frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
CLIENT_SECRETS_FILE = "client_secret_395607593037-genu2d5eb5trb8tj8nb497n48knu6omc.apps.googleusercontent.com.json"  # Download from Google Cloud Console
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.readonly'
]
REDIRECT_URI = "http://localhost:8000/auth/callback"
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

# In-memory storage for demo (use a proper database in production)
sessions = {}
tokens = {}

# Security scheme for API endpoints
security = HTTPBearer()

class TokenData(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_uri: str
    client_id: str
    client_secret: str
    scopes: list[str]

@app.on_event("startup")
async def startup_event():
    # This ensures the redirect URI is registered with the OAuth flow
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development

def get_flow():
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

@app.get("/")
async def root():
    return {"message": "Welcome to the FastAPI Gmail OAuth Example"}

@app.get("/auth/login")
async def login(request: Request):
    flow = get_flow()
    
    # Generate authorization URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    # Create a session ID and store the state
    session_id = str(uuid.uuid4())
    sessions[session_id] = {"state": state}
    
    response = RedirectResponse(url=authorization_url)
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    return response

@app.get("/auth/callback")
async def callback(request: Request, state: str, code: str = None, error: str = None):
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    
    # Get session ID from cookies
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(status_code=400, detail="Session not found")
    
    # Verify the state matches
    if sessions[session_id]["state"] != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    flow = get_flow()
    
    # Exchange authorization code for tokens
    flow.fetch_token(code=code)
    
    # Store the credentials
    credentials = flow.credentials
    token_data = TokenData(
        access_token=credentials.token,
        refresh_token=credentials.refresh_token,
        token_uri=credentials.token_uri,
        client_id=credentials.client_id,
        client_secret=credentials.client_secret,
        scopes=credentials.scopes
    )
    
    # Store tokens (in production, use a proper database)
    token_id = str(uuid.uuid4())
    tokens[token_id] = token_data.dict()
    
    # Clean up session
    del sessions[session_id]
    
    # Redirect to frontend with token (in production, use proper session handling)
    frontend_url = f"http://localhost:8000?token={token_id}"  # Adjust to your frontend
    response = RedirectResponse(url=frontend_url)
    response.delete_cookie("session_id")
    return response

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_id = credentials.credentials
    if token_id not in tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token_data = tokens[token_id]
    credentials = google.oauth2.credentials.Credentials(**token_data)
    
    if not credentials.valid:
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(GoogleRequest())
            # Update stored credentials
            token_data = TokenData(
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=credentials.scopes
            )
            tokens[token_id] = token_data.dict()
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return credentials

@app.get("/api/userinfo")
async def get_userinfo(credentials: google.oauth2.credentials.Credentials = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        # Get user info from Google
        userinfo = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {credentials.token}"}
        )
        
        if userinfo.status_code != 200:
            raise HTTPException(status_code=userinfo.status_code, detail="Failed to fetch user info")
        
        return userinfo.json()

@app.get("/api/emails")
async def get_emails(credentials: google.oauth2.credentials.Credentials = Depends(get_current_user)):
    # Build the Gmail service
    service = build(
        API_SERVICE_NAME,
        API_VERSION,
        credentials=credentials,
        static_discovery=False
    )
    
    # Get the list of messages
    results = service.users().messages().list(userId='me', maxResults=10).execute()
    messages = results.get('messages', [])
    
    email_list = []
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")
        email_list.append({'subject': subject, 'from': sender})
    
    return {"emails": email_list}

@app.get("/auth/logout")
async def logout(token_id: str):
    if token_id in tokens:
        del tokens[token_id]
    return {"message": "Logged out successfully"}

# For development: Simple frontend to test
@app.get("/test", response_class=HTMLResponse)
async def test_page():
    return """
    <html>
        <body>
            <h1>FastAPI Gmail OAuth Test</h1>
            <a href="/auth/login">Login with Google</a>
            <div id="result"></div>
            <script>
                // Simple frontend to display results
                async function fetchData(endpoint) {
                    const token = new URLSearchParams(window.location.search).get('token');
                    if (!token) return;
                    
                    const response = await fetch(endpoint, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const data = await response.json();
                    document.getElementById('result').innerHTML = 
                        `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                }
                
                // Check for token in URL
                const urlParams = new URLSearchParams(window.location.search);
                if (urlParams.has('token')) {
                    fetchData('/api/userinfo');
                    
                    // Add buttons to fetch data
                    document.body.innerHTML += `
                        <button onclick="fetchData('/api/userinfo')">Get User Info</button>
                        <button onclick="fetchData('/api/emails')">Get Emails</button>
                        <a href="/auth/logout?token=${urlParams.get('token')}">Logout</a>
                    `;
                }
            </script>
        </body>
    </html>
    """