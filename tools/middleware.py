import httpx
from fastapi import HTTPException, Request, Depends
from starlette.middleware.base import BaseHTTPMiddleware

# Shared function to validate access token
async def validate_access_token(token: str):
    url = "http://127.0.0.1:8000/api/auth/validate_token"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Invalid or expired token.")
        
        return response.json()  # Return the payload containing user data and role...

# Role middleware to check for token validity
class RoleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract token from Authorization header
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization token missing or invalid.")
        
        token = token[len("Bearer "):]  # Remove "Bearer " from the token string
        
        # Validate the token
        await validate_access_token(token)  # Use the shared validate_access_token function
        
        # Proceed to the next middleware or request handler
        response = await call_next(request)
        return response

# Role-required dependency function for role-based access control
def role_required(roles: list):
    async def role_dependency(token: str = Depends(get_bearer_token)):
        # Call the shared validate_access_token method to check the role
        payload = await validate_access_token(token)  # Await the async function
        
        if payload["role"] not in roles:
            raise HTTPException(status_code=403, detail="You are not authorized to access this resource.")
        
        return payload
    
    return role_dependency

# Helper function to extract bearer token from request
def get_bearer_token(request: Request):
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        return token[len("Bearer "):]
    raise HTTPException(status_code=401, detail="Authorization token missing or invalid.")
