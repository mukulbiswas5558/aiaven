from fastapi import HTTPException
from tools.database import Db
from main.src.apis.models.user import User,CreateUser,UpdateUser
from tools.token import create_access_token, create_refresh_token,get_password_hash
from typing import Dict
from asyncpg import Record
async def get_an_user_from_database(userid: int = None):
    db = await Db()

    result = await db.fetchrow("SELECT name, username, role FROM users WHERE id = $1", userid)

    db.close()

    if not userid:
        raise HTTPException(status_code=404, detail="User not found")

    return User(**result)


async def get_all_users_from_database():
    db = await Db()
    result = await db.fetch("SELECT id,name, username, role FROM users")
    db.close()
    return [User(**user) for user in result]

async def verify_user(username):
    db = await Db()
    result = await db.fetchrow("SELECT id, username, password FROM users WHERE username = $1", username)
    await db.close()  # Don't forget to close the database connection
    return result


async def create_user_service(user: CreateUser):
    # Initialize database connection
    db = await Db()

    # Check if the username already exists in the database
    query_check = "SELECT id FROM users WHERE username = $1"
    existing_user = await db.fetchrow(query_check, user.username)

    # If the username exists, raise an exception
    if existing_user:
        db.close()
        return {"message": "Username already exists. Please login."}
    
    query_check = "SELECT id FROM users WHERE phone = $1"
    existing_user_phone = await db.fetchrow(query_check, user.phone)

    # If the username exists, raise an exception
    if existing_user_phone:
        db.close()
        return {"message": "Phone Number already exists. Please login."}

    # Hash the password using the method in CreateUser model
    hashed_password = get_password_hash(user.password)

    # Insert the new user into the database with hashed password
    query = """
    INSERT INTO users (name, username, password, phone, department, employee_type, 
            job_position, company, bank_name, account_number, bank_country, 
            city, state, country, postal_code, shift_information, reporting_manager, 
            work_location, work_type, salary, branch, bank_address, bank_code_1, 
            bank_code_2, address_line_1, address_line_2, district) 
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27) 
    RETURNING id, name, username;
    """
    result = await db.fetchrow(query, user.name, user.username, hashed_password, user.phone, user.department, user.employee_type,
                               user.job_position, user.company, user.bank_name, user.account_number, user.bank_country,
                               user.city, user.state, user.country, user.postal_code, user.shift_information, user.reporting_manager,
                               user.work_location, user.work_type, user.salary, user.branch, user.bank_address, user.bank_code_1,
                               user.bank_code_2, user.address_line_1, user.address_line_2, user.district)

    if not result:
        db.close()
        raise HTTPException(status_code=500, detail="User registration failed.")
    
    query_roles = """
    INSERT INTO roles (user_id, super_admin, department_admin, super_checker, department_checker, department_maker)
    VALUES ($1, 1, 1, 0, 0, 0);
    """
    await db.execute(query_roles, result["id"])

    # Fetch roles where the value is 1
    query_get_roles = """
    SELECT 
        CASE WHEN super_admin = 1 THEN 'super_admin' END AS super_admin,
        CASE WHEN department_admin = 1 THEN 'department_admin' END AS department_admin,
        CASE WHEN super_checker = 1 THEN 'super_checker' END AS super_checker,
        CASE WHEN department_checker = 1 THEN 'department_checker' END AS department_checker,
        CASE WHEN department_maker = 1 THEN 'department_maker' END AS department_maker
    FROM roles
    WHERE user_id = $1;
    """
    role_result = await db.fetchrow(query_get_roles, result["id"])

    # Filter out None values and collect roles with value 1
    roles = [role for role in role_result.values() if role]

    # Prepare user data for token creation
    user_data = {
        "id": result["id"],
        "username": result["username"],
        "roles": roles  # Add roles to the user data
    }

    # Create access and refresh tokens
    access_token = create_access_token(data=user_data)
    refresh_token = create_refresh_token(data=user_data)

    db.close()

    # Return user details along with the tokens
    return {
        "user": {
            "id": result["id"],
            "username": result["username"],
            "roles": roles
        },
        "access_token": access_token,
        "refresh_token": refresh_token
    }

async def update_user_service(username: str, user_data: UpdateUser):

    try:
        db = await Db()  # Initialize database connection
        
        # Filter fields dynamically based on input
        fields_to_update = {key: value for key, value in user_data.dict().items() if value is not None}
        
        if not fields_to_update:
            raise HTTPException(status_code=400, detail="No fields provided to update.")

        # Build dynamic query
        set_clauses = ", ".join([f"{field} = ${index}" for index, field in enumerate(fields_to_update.keys(), start=1)])
        query = f"""
        UPDATE users
        SET {set_clauses}, updated_at = CURRENT_TIMESTAMP
        WHERE username = ${len(fields_to_update) + 1}
        RETURNING id, username, phone, department, shift_information, employee_type, job_position, 
                  reporting_manager, work_location, work_type, salary, company, bank_name, branch, 
                  bank_address, bank_code_1, bank_code_2, account_number, bank_country, address_line_1, 
                  address_line_2, city, district, state, country, postal_code, updated_at;
        """
        
        # Prepare query values
        values = list(fields_to_update.values()) + [username]

        # Execute the query
        async with db.transaction():
            updated_user: Record = await db.fetchrow(query, *values)

        if not updated_user:
            raise HTTPException(status_code=404, detail="update failed.")

        return {
            "message": "User updated successfully.",
            "user": dict(updated_user)  # Convert Record object to dict
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while updating the user.")