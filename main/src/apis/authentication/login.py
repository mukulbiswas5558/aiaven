from fastapi import HTTPException
from main.src.apis.database.user import verify_user
from hashlib import md5
from fastapi import HTTPException
from tools.token import create_access_token, verify_password

def is_already_loggedin(cookie):
    return True if cookie.get("token") else False

# Login the user and send JWT tokens in HttpOnly cookies
async def user_login(cookie, username, password):
    if not is_already_loggedin(cookie):
        user_data = await verify_user(username)
        
        if not user_data:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        
        hashed_password = user_data["password"]
        
        # Verify the password
        if verify_password(password, hashed_password):
            user_data = {
                "username": username,
                "role": "user"  # Assuming "user" role here; adjust if necessary
            }
            
            # Create JWT access token
            access_token = create_access_token(data=user_data)

            return {
                "message": "Login successful",
                "user": {"username": username, "role": "user"},
                "access_token": access_token  # Return token to be set in response at the route level
            }
        else:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
    else:
        return {"message": "Already logged in"}




