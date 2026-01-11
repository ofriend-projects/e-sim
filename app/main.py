from fastapi import FastAPI, Depends, Response, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from .user import fastapi_users, google_oauth_client, auth_backend, UserRead, UserUpdate, SECRET
from .models import Base, engine, get_async_session
from dotenv import load_dotenv
import logging
import jwt
from urllib.parse import unquote

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI()

@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"📥 {request.method} {request.url.path}")
    if request.query_params:
        logger.info(f"   Query params: {dict(request.query_params)}")
        
        # Special handling for OAuth callback to debug state token
        if request.url.path == "/auth/google/callback" and "state" in request.query_params:
            state_token = request.query_params["state"]
            logger.info("=" * 80)
            logger.info("🔍 OAUTH CALLBACK - Received State Token")
            logger.info("=" * 80)
            logger.info(f"📥 State Token (first 50 chars): {state_token[:50]}...")
            
            try:
                # Decode without verification to see contents
                decoded = jwt.decode(state_token, options={"verify_signature": False})
                logger.info(f"📋 State Token Decoded Contents:")
                logger.info(f"   - CSRF Token: {decoded.get('csrftoken', 'N/A')[:30]}...")
                logger.info(f"   - Audience: {decoded.get('aud', 'N/A')}")
                logger.info(f"   - Expiration: {decoded.get('exp', 'N/A')}")
                
                # Try to verify signature
                try:
                    verified = jwt.decode(state_token, SECRET, algorithms=["HS256"], audience="fastapi-users:oauth-state")
                    logger.info("✅ State Token Signature VERIFIED")
                except Exception as verify_error:
                    logger.error(f"❌ State Token Verification Failed: {verify_error}")
                    
            except Exception as e:
                logger.warning(f"⚠️  Could not decode state token: {e}")
            
            logger.info("=" * 80)
    
    response = await call_next(request)
    logger.info(f"📤 Response status: {response.status_code}")
    
    # Log authorization URL if it's the authorize endpoint
    if request.url.path == "/auth/google/authorize" and response.status_code == 200:
        try:
            import json
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            data = json.loads(body)
            if "authorization_url" in data:
                url = data["authorization_url"]
                logger.info("=" * 80)
                logger.info("🔑 OAUTH AUTHORIZE - State Token Created")
                logger.info("=" * 80)
                
                # Extract state from URL
                if "state=" in url:
                    state_start = url.index("state=") + 6
                    state_end = url.find("&", state_start)
                    if state_end == -1:
                        state_token = unquote(url[state_start:])
                    else:
                        state_token = unquote(url[state_start:state_end])
                    
                    logger.info(f"📝 State Token (first 50 chars): {state_token[:50]}...")
                    
                    try:
                        decoded = jwt.decode(state_token, options={"verify_signature": False})
                        logger.info(f"📋 State Token Contents:")
                        logger.info(f"   - CSRF Token: {decoded.get('csrftoken', 'N/A')[:30]}...")
                        logger.info(f"   - Audience: {decoded.get('aud', 'N/A')}")
                        logger.info(f"   - Expiration: {decoded.get('exp', 'N/A')}")
                    except Exception as e:
                        logger.warning(f"⚠️  Could not decode: {e}")
                
                logger.info("=" * 80)
            
            # Recreate response with body
            from starlette.responses import Response
            response = Response(content=body, status_code=response.status_code, 
                              headers=dict(response.headers), media_type=response.media_type)
        except Exception as e:
            logger.warning(f"Could not parse response: {e}")
    
    return response

@app.on_event("startup")
async def on_startup():
    logger.info("🚀 Application starting up...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables created/verified")

# Simple login page
@app.get("/login", response_class=HTMLResponse)
async def login():
    """Display a login page with Google OAuth"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login with Google</h1>
        <div id="login-section">
            <button onclick="loginWithGoogle()">Login with Google</button>
        </div>
        <div id="user-section" style="display:none;">
            <h2>Welcome, <span id="user-email"></span>!</h2>
            <button onclick="testProtectedRoute()">Test Protected Route</button>
            <button onclick="logout()">Logout</button>
            <pre id="result"></pre>
        </div>
        
        <script>
        // Check if we have a token in localStorage
        window.onload = function() {
            const token = localStorage.getItem('access_token');
            if (token) {
                showUserSection();
            }
            
            // Handle OAuth callback
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            if (code) {
                // We're on the callback, but the token is in the response
                // Show message to user
                document.getElementById('result').textContent = 'Authentication successful! Token received.';
            }
        };
        
        async function loginWithGoogle() {
            // Get the authorization URL, but modify redirect_uri to use our custom callback
            const response = await fetch('/auth/google/authorize');
            const data = await response.json();
            
            // Replace the callback URL to use our redirect version
            let authUrl = data.authorization_url;
            authUrl = authUrl.replace(
                encodeURIComponent('http://127.0.0.1:8000/auth/google/callback'),
                encodeURIComponent('http://127.0.0.1:8000/auth/google/callback-redirect')
            );
            
            // Redirect to Google login
            window.location.href = authUrl;
        }
        
        function showUserSection() {
            document.getElementById('login-section').style.display = 'none';
            document.getElementById('user-section').style.display = 'block';
        }
        
        async function testProtectedRoute() {
            const token = localStorage.getItem('access_token');
            if (!token) {
                alert('No token found! Please login first.');
                return;
            }
            
            try {
                const response = await fetch('/protected', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('result').textContent = JSON.stringify(data, null, 2);
                    document.getElementById('user-email').textContent = data.message;
                } else {
                    document.getElementById('result').textContent = `Error: ${response.status} - ${await response.text()}`;
                }
            } catch (error) {
                document.getElementById('result').textContent = `Error: ${error.message}`;
            }
        }
        
        function logout() {
            localStorage.removeItem('access_token');
            location.reload();
        }
        </script>
    </body>
    </html>
    """

# Custom callback success page that receives and stores the token
@app.get("/callback/success", response_class=HTMLResponse)
async def callback_success():
    """Display token and auto-store in localStorage"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Login Success</title></head>
    <body>
        <h1>✅ Login Successful!</h1>
        <p id="status">Storing your session...</p>
        <script>
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        
        if (token) {
            localStorage.setItem('access_token', token);
            document.getElementById('status').innerHTML = 
                '✅ Session saved!<br>Redirecting to home page...';
            setTimeout(() => window.location.href = '/login', 1500);
        } else {
            document.getElementById('status').innerHTML = 
                '⚠️ No token received. <a href="/login">Return to login</a>';
        }
        </script>
    </body>
    </html>
    """

# Custom OAuth callback wrapper that redirects instead of returning JSON
@app.get("/auth/google/callback-redirect")
async def google_callback_redirect(request: Request):
    """Handle Google OAuth callback and redirect to success page with token"""
    logger.info("🔄 Custom callback wrapper - will redirect with token")
    
    # Import the callback handler from fastapi-users
    from fastapi_users.router.oauth import generate_state_token
    from httpx import AsyncClient
    
    # Get the code and state from query params
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    
    if not code or not state:
        logger.error("❌ Missing code or state parameter")
        return RedirectResponse(url="/login?error=missing_params")
    
    try:
        # Verify state token
        import jwt
        verified_state = jwt.decode(state, SECRET, algorithms=["HS256"], audience="fastapi-users:oauth-state")
        logger.info("✅ State token verified in custom callback")
        
        # Exchange code for Google tokens
        async with AsyncClient() as client:
            token_response = await google_oauth_client.get_access_token(code, "http://127.0.0.1:8000/auth/google/callback-redirect")
            access_token = token_response["access_token"]
            
            # Get user info from Google
            user_id, user_email = await google_oauth_client.get_id_email(access_token)
            
        logger.info(f"📧 Google user authenticated: {user_email}")
        
        # Get or create user in database
        from .user import get_user_manager
        from .models import get_user_db, get_async_session
        
        async for session in get_async_session():
            async for user_db in get_user_db(session):
                async for user_manager in get_user_manager(user_db):
                    # Use the oauth_callback method to handle user creation/update
                    user = await user_manager.oauth_callback(
                        oauth_name="google",
                        access_token=access_token,
                        account_id=user_id,
                        account_email=user_email,
                        expires_at=token_response.get("expires_at"),
                        refresh_token=token_response.get("refresh_token"),
                        request=request,
                        associate_by_email=True,
                        is_verified_by_default=True
                    )
                    
                    logger.info(f"✅ User processed: {user.email} (ID: {user.id})")
                    
                    # Generate JWT token for our app
                    from .user import get_jwt_strategy
                    strategy = get_jwt_strategy()
                    jwt_token = await strategy.write_token(user)
                    
                    logger.info(f"🎫 JWT token generated, redirecting to success page")
                    
                    # Redirect to success page with token
                    return RedirectResponse(
                        url=f"/callback/success?token={jwt_token}",
                        status_code=303
                    )
        
    except jwt.ExpiredSignatureError:
        logger.error("❌ State token expired")
        return RedirectResponse(url="/login?error=state_expired")
    except jwt.InvalidSignatureError:
        logger.error("❌ Invalid state token signature")
        return RedirectResponse(url="/login?error=invalid_state")
    except Exception as e:
        logger.error(f"❌ OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(url="/login?error=oauth_failed")

# Google OAuth routes - keep original for API usage
app.include_router(
    fastapi_users.get_oauth_router(
        google_oauth_client, 
        auth_backend, 
        SECRET
    ),
    prefix="/auth/google",
    tags=["auth"],
)

# Current user endpoint (protected)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"],
)

# Example protected route
from .user import fastapi_users
current_active_user = fastapi_users.current_user(active=True)

@app.get("/protected")
async def protected_route(user=Depends(current_active_user)):
    logger.info(f"🔐 Protected route accessed by user: {user.email} (ID: {user.id})")
    return {"message": f"Hello {user.email}!", "user_id": str(user.id)}

# Debug/Admin endpoints to view database contents
@app.get("/debug/users")
async def debug_users(session=Depends(get_async_session)):
    """Get all users from database"""
    from sqlalchemy import select
    from .models import User, OAuthAccount
    
    result = await session.execute(select(User))
    users = result.scalars().all()
    
    users_data = []
    for user in users:
        users_data.append({
            "id": str(user.id),
            "email": user.email,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "is_superuser": user.is_superuser,
            "oauth_accounts_count": len(user.oauth_accounts) if user.oauth_accounts else 0
        })
    
    return {
        "total_users": len(users_data),
        "users": users_data
    }

@app.get("/debug/oauth-accounts")
async def debug_oauth_accounts(session=Depends(get_async_session)):
    """Get all OAuth accounts from database"""
    from sqlalchemy import select
    from .models import OAuthAccount
    
    result = await session.execute(select(OAuthAccount))
    oauth_accounts = result.scalars().all()
    
    accounts_data = []
    for account in oauth_accounts:
        accounts_data.append({
            "id": str(account.id),
            "user_id": str(account.user_id),
            "oauth_name": account.oauth_name,
            "account_id": account.account_id,
            "account_email": account.account_email,
            "access_token": account.access_token[:20] + "..." if account.access_token else None,
            "expires_at": account.expires_at
        })
    
    return {
        "total_accounts": len(accounts_data),
        "oauth_accounts": accounts_data
    }

@app.get("/debug/database")
async def debug_database(session=Depends(get_async_session)):
    """Get complete database overview"""
    from sqlalchemy import select
    from .models import User, OAuthAccount
    
    # Get all users with their OAuth accounts
    result = await session.execute(select(User))
    users = result.unique().scalars().all()  # Use .unique() for joined eager loads
    
    database_data = []
    for user in users:
        user_data = {
            "user": {
                "id": str(user.id),
                "email": user.email,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "is_superuser": user.is_superuser,
                "hashed_password": user.hashed_password[:30] + "..." if user.hashed_password else None
            },
            "oauth_accounts": []
        }
        
        for oauth in user.oauth_accounts:
            user_data["oauth_accounts"].append({
                "oauth_name": oauth.oauth_name,
                "account_id": oauth.account_id,
                "account_email": oauth.account_email,
                "access_token_preview": oauth.access_token[:20] + "..." if oauth.access_token else None,
                "expires_at": oauth.expires_at
            })
        
        database_data.append(user_data)
    
    return {
        "total_users": len(database_data),
        "database": database_data
    }