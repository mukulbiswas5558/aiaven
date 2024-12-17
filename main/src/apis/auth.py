from fastapi import APIRouter, HTTPException,Depends, Request, Response, status
from main.src.apis.models.user import CreateUser, UserCredentials
from main.src.apis.database.user import (
    create_user_service,
)
from fastapi.responses import JSONResponse

from main.src.apis.authentication.login import user_login
from tools.token import create_access_token,validate_refresh_token,get_bearer_token

router = APIRouter(prefix="/api/auth", tags=["AUTH"])





@router.post("/register")
async def create_user(user: CreateUser):
    try:

        # Pass the user to the service to save
        return await create_user_service(user)

    except Exception as e:
        raise HTTPException(status_code=400, detail="Error creating user: ")
    
@router.post("/login")
async def login(request: Request, response: Response, user: UserCredentials):
    cookie = request.cookies  # Extract cookies from the request

    # Call the login function and get the result
    login_result = await user_login(cookie, user.username, user.password)

    # If successful, set the JWT token in an HttpOnly cookie
    if "access_token" in login_result:
        response.set_cookie(
            key="access_token",
            value=login_result["access_token"],
            httponly=True,
            max_age=60 * 15  # Token expires in 15 minutes
        )
        return JSONResponse(
            content={
                "message": login_result["message"],
                "user": login_result["user"]
            },
            status_code=200
        )
    
    # If already logged in or any other response, return as-is
    return login_result


@router.post("/refresh")
async def refresh_token(response: Response, token: str = Depends(get_bearer_token)):
    """
    Refresh the access token using a valid refresh token.
    """
    # Validate the refresh token
    payload = validate_refresh_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token."
        )

    # Generate a new access token
    user_data = {
        "username": payload["username"],
        "role": payload["role"]
    }
    new_access_token = create_access_token(data=user_data)

    # Set the new access token in HttpOnly cookies
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=True,  # Make sure to use secure cookies in production (for HTTPS)
        samesite="Strict",  # Adjust the SameSite policy based on your needs
    )

    return JSONResponse(
        content={"message": "Token refreshed successfully"},
        status_code=status.HTTP_200_OK,
    )