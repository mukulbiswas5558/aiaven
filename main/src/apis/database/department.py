from fastapi import HTTPException
from tools.database import Db
from main.src.apis.models.department import Department
from typing import Dict
from asyncpg import Record
# Fetch a single department by ID
async def get_a_department_from_database(department_id: int):
    db = await Db()

    result = await db.fetchrow(
        "SELECT id, code, description, manager_id, budget, location, phone, email, created_at, updated_at FROM departments WHERE id = $1",
        department_id
    )

    db.close()

    if not result:
        raise HTTPException(status_code=404, detail="Department not found")

    return Department(**result)

# Fetch all departments
async def get_all_departments_from_database():
    db = await Db()
    result = await db.fetch(
        "SELECT id, code, description, manager_id, budget, location, phone, email, created_at, updated_at FROM departments"
    )
    db.close()
    return [Department(**department) for department in result]

# Create a new department
async def create_department_service(department: Department):
    db = await Db()

    # Check if the department code already exists
    query_check = "SELECT id FROM departments WHERE code = $1"
    existing_department = await db.fetchrow(query_check, department.code)

    if existing_department:
        db.close()
        return {"message": "Department code already exists."}

    # Insert the new department into the database
    query = """
    INSERT INTO departments (code, description, manager_id, budget, location, phone, email)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, code, description, manager_id, budget, location, phone, email, created_at, updated_at;
    """
    result = await db.fetchrow(
        query,
        department.code,
        department.description,
        department.manager_id,
        department.budget,
        department.location,
        department.phone,
        department.email
    )

    if not result:
        db.close()
        raise HTTPException(status_code=500, detail="Department creation failed.")

    db.close()
    return Department(**result)

# Update an existing department
async def update_department_service(department_id: int, department_data: Dict):
    db = await Db()

    # Filter fields dynamically based on input
    fields_to_update = {key: value for key, value in department_data.items() if value is not None}

    if not fields_to_update:
        raise HTTPException(status_code=400, detail="No fields provided to update.")

    # Build dynamic query
    set_clauses = ", ".join([f"{field} = ${index}" for index, field in enumerate(fields_to_update.keys(), start=1)])
    query = f"""
    UPDATE departments
    SET {set_clauses}, updated_at = CURRENT_TIMESTAMP
    WHERE id = ${len(fields_to_update) + 1}
    RETURNING id, code, description, manager_id, budget, location, phone, email, created_at, updated_at;
    """

    # Prepare query values
    values = list(fields_to_update.values()) + [department_id]

    # Execute the query
    async with db.transaction():
        updated_department: Record = await db.fetchrow(query, *values)

    if not updated_department:
        raise HTTPException(status_code=404, detail="Update failed.")

    db.close()
    return Department(**updated_department)

# Delete a department
async def delete_department_service(department_id: int):
    db = await Db()

    query = "DELETE FROM departments WHERE id = $1 RETURNING id, code;"
    result = await db.fetchrow(query, department_id)

    db.close()

    if not result:
        raise HTTPException(status_code=404, detail="Department not found or could not be deleted.")

    return {"message": "Department deleted successfully.", "department": dict(result)}