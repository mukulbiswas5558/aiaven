from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional



class User(BaseModel):
    name : str
    username: str
    role: str

class UserCredentials(BaseModel):
    username: str
    password: str


class CreateUser(BaseModel):
    # Required fields
    name: str = Field(..., min_length=2, max_length=100, description="User's full name")
    username: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="Password with at least 8 characters")
   

    # Fields that are now required
    phone: str = Field(..., description="User's phone number")
    department: str = Field(..., description="Department of the user")
    employee_type: str = Field(..., description="Type of employee (e.g., permanent, contract)")
    job_position: str = Field(..., description="Job position of the user")
    company: str = Field(..., description="Company name")
    bank_name: str = Field(..., description="Bank name")
    account_number: str = Field(..., description="Bank account number")
    bank_country: str = Field(..., description="Bank country")
    city: str = Field(..., description="City")
    state: str = Field(..., description="State")
    country: str = Field(..., description="Country")
    postal_code: str = Field(..., description="Postal code")
    department_id: str = Field(..., description="Department id code")
    role: str = Field(default="user", description="Role of the user (default: user)")
    # Optional fields
    shift_information: Optional[str] = None
    reporting_manager: Optional[str] = None
    work_location: Optional[str] = None
    work_type: Optional[str] = None
    salary: Optional[str] = None
    branch: Optional[str] = None
    bank_address: Optional[str] = None
    bank_code_1: Optional[str] = None
    bank_code_2: Optional[str] = None
    address_line_1: Optional[str] = None
    address_line_2: Optional[str] = None
    district: Optional[str] = None
    

    # Password validation
    @field_validator("password")
    def validate_password_strength(cls, value):
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one number")
        if not any(char.isalpha() for char in value):
            raise ValueError("Password must contain at least one letter")
        return value

    # Phone number validation (10 digits)
    @field_validator("phone", mode="before")
    def validate_phone_number(cls, value):
        if not value.isdigit():
            raise ValueError("Phone number must contain only digits.")
        if len(value) != 10:
            raise ValueError("Phone number must be exactly 10 digits.")
        return value

    # Numeric field validation
    @field_validator("account_number", "postal_code", "department_id", mode="before")
    def validate_numeric_fields(cls, value, info):
        value_str = str(value)  # Ensure the value is treated as a string
        if not value_str.isdigit():
            field_name = info.field_name.replace('_', ' ').title()  # Use info.field_name
            raise ValueError(f"{field_name} must contain only numbers.")
        return value_str  # Return as a string to avoid further issues

    # Alphabetic field validation
    @field_validator("city", "state", "country", "bank_country", "department", "job_position", "company", mode="before")
    def validate_string_fields(cls, value, info):
        if not value.replace(" ", "").isalpha():
            field_name = info.field_name.replace('_', ' ').title()  # Use info.field_name
            raise ValueError(f"{field_name} must contain only alphabetic characters.")
        return value
    
class UpdateUser(BaseModel):
    phone: Optional[str] = None
    department: Optional[str] = None
    shift_information: Optional[str] = None
    employee_type: Optional[str] = None
    job_position: Optional[str] = None
    reporting_manager: Optional[str] = None
    work_location: Optional[str] = None
    work_type: Optional[str] = None
    salary: Optional[str] = None
    company: Optional[str] = None
    bank_name: Optional[str] = None
    branch: Optional[str] = None
    bank_address: Optional[str] = None
    bank_code_1: Optional[str] = None
    bank_code_2: Optional[str] = None
    account_number: Optional[str] = None
    bank_country: Optional[str] = None
    address_line_1: Optional[str] = None
    address_line_2: Optional[str] = None
    city: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
