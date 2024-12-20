from fastapi import APIRouter, HTTPException, Depends
from main.src.apis.models.user import CreateUser, UserCredentials
from main.src.apis.database.user import (
    create_user_service,
)

from main.src.apis.authentication.login import user_login
from tools.token import create_access_token,validate_refresh_token,get_bearer_token,verify_password,validate_access_token
from main.src.apis.database.user import verify_user

router = APIRouter(prefix="/api/auth", tags=["AUTH"])





@router.post("/register")
async def create_user(user: CreateUser):
    try:

        # Pass the user to the service to save
        return await create_user_service(user)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating user: {e}")
    
@router.post("/login")
async def login(user: UserCredentials):
    # Verify user details
    user_data = await verify_user(user.username)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    hashed_password = user_data["password"]
    
    # Verify the password
    if verify_password(user.password, hashed_password):
        token_data = {
            "username": user.username,
            "role": user_data["role"]  # Assuming "user" role; adjust if necessary
        }
        
        # Create JWT access token
        access_token = create_access_token(data=token_data)
        
        return {
            "message": "Login successful",
            "user": token_data,
            "access_token": access_token
        }
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")


# @router.post("/login")
# async def login(request: Request, response: Response, user: UserCredentials):
#     cookie = request.cookies  # Extract cookies from the request

#     # Call the login function and get the result
#     login_result = await user_login(cookie, user.username, user.password)

#     # If successful, set the JWT token in an HttpOnly cookie
#     if "access_token" in login_result:
#         response.set_cookie(
#             key="access_token",
#             value=login_result["access_token"],
#             httponly=True,
#             max_age=60 * 15  # Token expires in 15 minutes
#         )
#         return JSONResponse(
#             content={
#                 "message": login_result["message"],
#                 "user": login_result["user"]
#             },
#             status_code=200
#         )
    
#     # If already logged in or any other response, return as-is
#     return login_result


@router.post("/refresh")
async def refresh_token(token: str = Depends(get_bearer_token)):
    """
    Refresh the access token using a valid refresh token.
    """
    payload = validate_refresh_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    # Generate a new access token
    user_data = {
        "username": payload["username"],
        "role": payload["role"]
    }
    new_access_token = create_access_token(data=user_data)

    return {
        "access_token": new_access_token
    }

@router.post("/validate_token")
async def validate_token(
    token: str = Depends(get_bearer_token)
):
    """
    Validate the JWT token and return decoded token details.
    """
    try:
        # Validate the token
        payload = validate_access_token(token)

        # Extract the username and role from the payload
        username = payload.get("username")
        role = payload.get("role")

        if not username or not role:
            raise HTTPException(status_code=401, detail="Invalid token payload. Required fields are missing.")

        # If token is valid, return success and decoded payload
        return {
            "message": "Token validation successful",
            "role": role,
            "user": {
                "username": username
                
            }
        }

    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")