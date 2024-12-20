from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional

class Department(BaseModel):
    name: str = Field(..., min_length=1, max_length=50, description="Unique department code")
    description: Optional[str] = Field(None, description="Department description")
    manager_id: Optional[int] = Field(None, description="User ID of the department manager")
    location: str = Field(..., min_length=1, max_length=225, description="Department location")
    phone: str = Field(..., min_length=1, max_length=50, description="Department contact phone")
    email: EmailStr = Field(..., description="Department email address")
   

    # Code validation
  

    

    # Phone number validation
    @field_validator("phone", mode="before")
    def validate_phone_number(cls, value):
        if not value.isdigit():
            raise ValueError("Phone number must contain only digits.")
        if len(value) != 10:
            raise ValueError("Phone number must be exactly 10 digits.")
        return value

    # Location validation
    @field_validator("location", mode="before")
    def validate_location(cls, value):
        if not value.strip():
            raise ValueError("Location cannot be empty.")
        return value

    # Email validation (handled by EmailStr)
    # Manager ID validation
    @field_validator("manager_id", mode="before")
    def validate_manager_id(cls, value):
        if value is not None and value <= 0:
            raise ValueError("Manager ID must be a positive integer.")
        return value