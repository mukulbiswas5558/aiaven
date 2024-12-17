from fastapi import APIRouter, HTTPException,Depends
from main.src.apis.models.user import User,UpdateUser
from main.src.apis.database.user import (
    get_an_user_from_database,
    get_all_users_from_database,
    update_user_service
)
from tools.token import validate_access_token,get_bearer_token
from fastapi import APIRouter, HTTPException



router = APIRouter(prefix="/api/user", tags=["USERS"])


@router.get("/get-user", response_model=User)
async def get_user(userid: int = None):
    """
    Get a single user from the database using the user ID
    """
    user_data = await get_an_user_from_database(userid)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    return user_data


@router.get("/get-all-users", response_model=list[User])
async def get_all_users():
    """
    Get all users from the database
    """
    return await get_all_users_from_database()


@router.put("/update")
async def update_user(
    user: UpdateUser,
    token: str = Depends(get_bearer_token)
):
    """
    Updates a user's details after validating the JWT token.
    """
    try:
        # Validate the token
        payload = validate_access_token(token)
        print(f"Decoded Token: {payload}")

        # Extract username from the token payload
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload. Username not found.")

        # Call the service to update the user
        result = await update_user_service(username, user)
        return result
    
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")