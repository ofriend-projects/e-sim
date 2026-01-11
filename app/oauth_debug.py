"""
Debug wrapper for OAuth flow to trace state token creation and validation
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2AuthorizationCodeBearer
from httpx_oauth.oauth2 import OAuth2Token
import jwt

logger = logging.getLogger(__name__)

# Monkey patch to add debug logging
original_generate_state_token = None

def debug_oauth_authorize(router):
    """Wrap the authorize endpoint to log state token creation"""
    
    @router.get("/authorize")
    async def authorize_debug(request: Request):
        logger.info("=" * 80)
        logger.info("🔑 OAUTH AUTHORIZE - Creating State Token")
        logger.info("=" * 80)
        
        # The original route will be called
        # We'll see the state token in the authorization_url
        from fastapi_users.router.oauth import generate_state_token
        
        # Get the original response
        response = await router.routes[0].endpoint(request)
        
        if hasattr(response, 'body'):
            import json
            body = json.loads(response.body)
            if 'authorization_url' in body:
                url = body['authorization_url']
                # Extract state from URL
                if 'state=' in url:
                    state_start = url.index('state=') + 6
                    state_end = url.find('&', state_start)
                    if state_end == -1:
                        state_token = url[state_start:]
                    else:
                        state_token = url[state_start:state_end]
                    
                    logger.info(f"📝 State Token Created: {state_token[:50]}...")
                    
                    # Try to decode it (it's a JWT)
                    try:
                        from urllib.parse import unquote
                        decoded_state = unquote(state_token)
                        # Don't verify signature, just decode to see contents
                        decoded = jwt.decode(decoded_state, options={"verify_signature": False})
                        logger.info(f"📋 State Token Contents:")
                        logger.info(f"   - CSRF Token: {decoded.get('csrftoken', 'N/A')}")
                        logger.info(f"   - Audience: {decoded.get('aud', 'N/A')}")
                        logger.info(f"   - Expiration: {decoded.get('exp', 'N/A')}")
                    except Exception as e:
                        logger.warning(f"⚠️  Could not decode state token: {e}")
                
        logger.info("=" * 80)
        return response


def log_callback_state(state: str, secret: str):
    """Log state token validation in callback"""
    logger.info("=" * 80)
    logger.info("🔍 OAUTH CALLBACK - Validating State Token")
    logger.info("=" * 80)
    logger.info(f"📥 Received State Token: {state[:50]}...")
    
    try:
        # Decode without verification first to see contents
        decoded = jwt.decode(state, options={"verify_signature": False})
        logger.info(f"📋 State Token Contents:")
        logger.info(f"   - CSRF Token: {decoded.get('csrftoken', 'N/A')}")
        logger.info(f"   - Audience: {decoded.get('aud', 'N/A')}")
        logger.info(f"   - Expiration: {decoded.get('exp', 'N/A')}")
        
        # Now verify with secret
        verified = jwt.decode(state, secret, algorithms=["HS256"], audience="fastapi-users:oauth-state")
        logger.info("✅ State Token Signature VALID")
        logger.info(f"   - Verified CSRF: {verified.get('csrftoken', 'N/A')}")
        
    except jwt.ExpiredSignatureError:
        logger.error("❌ State Token EXPIRED")
        raise
    except jwt.InvalidSignatureError:
        logger.error("❌ State Token INVALID SIGNATURE")
        raise
    except jwt.InvalidAudienceError:
        logger.error("❌ State Token INVALID AUDIENCE")
        raise
    except Exception as e:
        logger.error(f"❌ State Token Validation Error: {e}")
        raise
    
    logger.info("=" * 80)
    return verified
