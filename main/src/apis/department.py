from fastapi import APIRouter, HTTPException, Depends
from main.src.apis.models.department import Department
from tools.token import validate_access_token, get_bearer_token
from tools.middleware import role_required

from typing import Dict
from main.src.apis.database.department import (
    get_a_department_from_database,
    get_all_departments_from_database,
    create_department_service,
    update_department_service,
    delete_department_service
)

router = APIRouter(prefix="/api/department", tags=["DEPARTMENT"])

# Add middleware for role-based access control

# Route to fetch a single department by ID
@router.get("/get-department/{department_id}")
async def get_department(department_id: int):
    """
    Fetch a single department by ID
    """
    department = await get_a_department_from_database(department_id)
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    return department


# Route to fetch all departments
@router.get("/get-all-departments")
async def get_all_departments():
    """
    Fetch all departments
    """
    return await get_all_departments_from_database()


# Route to create a new department (requires specific roles)
@router.post("/create-department")
async def create_department(department: Department, user=Depends(role_required(["department_maker", "super_admin"]))):
    """
    Create a new department
    """
    try:
        return await create_department_service(department)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating department: {e}")


# Route to update an existing department (requires specific roles)
@router.put("/update-department/{department_id}")
async def update_department(
    department_id: int,
    department_data: Dict,
    token: str = Depends(get_bearer_token)
):
    """
    Update an existing department
    """
    try:
        # Validate the token
        payload = validate_access_token(token)
        print(f"Decoded Token: {payload}")

        # Call the service to update the department
        updated_department = await update_department_service(department_id, department_data)
        return updated_department

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


# Route to delete a department by ID (requires specific roles)
@router.delete("/delete-department/{department_id}")
async def delete_department(department_id: int, user=Depends(role_required(["department_admin", "super_admin"]))):
    """
    Delete a department by ID
    """
    try:
        return await delete_department_service(department_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error deleting department: {e}")
