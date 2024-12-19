import httpx
from fastapi import HTTPException, Request, Depends
from starlette.middleware.base import BaseHTTPMiddleware

# Role middleware to check for token validity and role-based access
class RoleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip role validation for public routes
        if self.is_public_route(request.url.path):
            return await call_next(request)

        # Extract token from Authorization header
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization token missing or invalid.")
        
        token = token[len("Bearer "):]  # Remove "Bearer " from the token string
        
        # Validate the token and check role
        await self.validate_access_token(token)
        
        # Proceed to the next middleware or request handler
        response = await call_next(request)
        return response

    def is_public_route(self, path: str):
        # List public routes that do not require role validation
        public_routes = ["/login", "/register", "/api/auth/refresh"]
        return path in public_routes

    async def validate_access_token(self, token: str):
        url = "http://127.0.0.1:8000/api/auth/refresh"
        headers = {"Authorization": f"Bearer {token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers)
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Invalid or expired token.")
            
            data = response.json()
            role = data.get("role")
            
            # Check if the role is valid for access
            if not self.is_role_allowed(role):
                raise HTTPException(status_code=403, detail="You are not authorized to access this resource.")

    def is_role_allowed(self, role: str):
        # Define allowed roles for accessing the API
        allowed_roles = ["super_admin", "department_maker", "department_admin", "department_checker", "super_checker", "user"]
        
        # Allow access if the role is one of the allowed roles
        return role in allowed_roles

# Role-required dependency function for role-based access control
def role_required(roles: list):
    async def role_dependency(token: str = Depends(get_bearer_token)):
        # Call the validate_access_token method to check the role
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

# Function to validate the access token and get user role (used by both middleware and role_required)
async def validate_access_token(token: str):
    url = "http://127.0.0.1:8000/api/auth/refresh"
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Invalid or expired token.")
        
        return response.json()  # Return the payload containing user data and role
