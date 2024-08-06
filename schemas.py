from pydantic import BaseModel
from decouple import config
from datetime import datetime

CSRF_KEY = config('CSRF_KEY')

class CsrfSettings(BaseModel):
    secret_key: str = CSRF_KEY

class Customer(BaseModel):
    customer_id: str
    name: str
    email: str

class CustomerInfo(BaseModel):
    customer_id: str
    name: str
    email: str

class CustomerRegisterBody(BaseModel):
    name: str
    email: str
    password: str

class CustomerLoginBody(BaseModel):
    email: str
    password: str

class SuccessMsg(BaseModel):
    message: str

class Booking(BaseModel):
    booking_id: str
    customer_id: str
    appointment_date: datetime
    details: str

class BookingBody(BaseModel):
    customer_id: str
    appointment_date: datetime
    details: str

class Csrf(BaseModel):
    csrf_token: str