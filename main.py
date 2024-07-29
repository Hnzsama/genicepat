from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Query
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import base64
from pymongo import DESCENDING
from bson import ObjectId
import re
from PIL import Image
from io import BytesIO
from config import get_database_connection, SECRET_KEY, ALGORITHM
from urllib.parse import unquote
from smtplib import SMTPException
from babel.dates import format_datetime
from babel import Locale, numbers, dates
from locale import setlocale, LC_TIME
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi.middleware.cors import CORSMiddleware
import smtplib
import json
from datetime import datetime
from pytz import timezone, utc


app = FastAPI()
client, db, foto_collection, timezone_collection, currency_collection, culture_collection, campaigns_collection, accounts_collection, clients_collection, user_collection, dashboard_collection, history_collection, metrics_collection, profil_collection, settings_collection, tenant_collection = get_database_connection("mongodb+srv://abdiirf1y:abdiirf2134@umax.diiz7t7.mongodb.net/")
origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://192.168.1.57:3000",
    "umax-dashboard.vercel.app"
]


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)
    
# Allow these methods to be used
methods = ["GET", "POST", "PUT", "DELETE"]

headers = ["Content-Type", "Authorization"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enkripsi dan verifikasi kata sandi
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_jwt_token(email, id: str, company: str, staff_name: str, tenant_id: str, roles: str) -> str:
    payload = {"email": email, "user_id": str(id), "company_name": company, "name": staff_name, "tenant_id": tenant_id, "roles": roles ,"exp": datetime.utcnow() + timedelta(hours=12)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM).encode("utf-8")
    return token

def decode_jwt_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload

def get_current_user(roles: str = Depends(HTTPBearer())) -> str:
    credentials_data = decode_jwt_token(roles.credentials)
    roles = credentials_data.get("roles", [])
    if not roles:
        raise HTTPException(status_code=403, detail="ini get roles")
    return roles

def get_user_culture(user_id):
    user_data = user_collection.find_one({"_id": ObjectId(user_id)})
    return user_data.get("culture") if user_data else None

def get_user_timezone(user_id):
    user_data = user_collection.find_one({"_id": ObjectId(user_id)})
    return user_data.get("timezone_name") if user_data else None

def get_campaign_culture(campaign_id: str):
    user_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
    return user_data.get("culture") if user_data else None

def get_campaign_timezone(campaign_id: str):
    user_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
    return user_data.get("timezone_name") if user_data else None

def format_timestamp(timestamp, culture, timezone_name):
    localized_time = convert_timestamp_to_timezone(timestamp, timezone_name)
    return format_datetime(localized_time, locale=culture)

def convert_timestamp_to_timezone(timestamp, timezone_name):
    # Memastikan bahwa timestamp dalam bentuk string
    timestamp_str = str(timestamp)
    utc_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
    user_timezone = timezone(timezone_name)
    localized_time = utc_time.replace(tzinfo=timezone("UTC")).astimezone(user_timezone)
    return localized_time

def get_current_user_perusahaan(perusahaan: str = Depends(HTTPBearer())) -> str:
    credentials_data = decode_jwt_token(perusahaan.credentials)
    perusahaan = credentials_data.get("tenant_id", []
                                      
                                      )
    if not perusahaan:
        raise HTTPException(status_code=403, detail="ini get perusahaan")
    return perusahaan

def get_current_staff_id(_id:str = Depends(HTTPBearer())) -> str:
    credentials_data = decode_jwt_token(_id.credentials)
    # sekolah = credentials_data.get("nama_sekolah", None)
    guruID = credentials_data.get("_id", [])
    if not guruID:
        raise HTTPException(status_code=403, detail="ini get userID tapi salah")
    return guruID

#fungsi menambahkan id_tenant berdasarkan nama Sekolah
def get_nama_tenant(tenant_collection, tenant_id):
    obj_id = ObjectId(tenant_id)
    school = tenant_collection.find_one({"_id": obj_id})
    
    if school:
        return str(school["company"])
    else:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Perusahaan tidak ditemukan", "Output": ""})
    
def get_current_user_tenant_id(roles: str = Depends(HTTPBearer())) -> str:
    credentials_data = decode_jwt_token(roles.credentials)
    tenant_id = credentials_data.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID tidak ditemukan dalam token JWT")
    return tenant_id

def get_current_user_user_id(roles: str = Depends(HTTPBearer())) -> str:
    credentials_data = decode_jwt_token(roles.credentials)
    staff_id = credentials_data.get("user_id", "")
    if not staff_id:
        raise HTTPException(status_code=403, detail="User ID tidak ditemukan dalam token JWT")
    return staff_id


# Menggantikan 'verify_password' dengan fungsi yang sesuai untuk memverifikasi kata sandi
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Fungsi untuk mendapatkan koleksi pengguna dari MongoDB
def get_user_collection():
    # Ganti ini sesuai dengan cara Anda mendapatkan koneksi ke MongoDB
    return get_database_connection

# Fungsi untuk mendapatkan token saat ini
def get_current_token(token: str = Depends( decode_jwt_token)):
    return token


# Rute untuk pendaftaran pengguna
@app.post("/register", tags=["Akun"])
def register_user(
    tenantId: str = Query(None,description="Hanya Untuk SuperAdmin" ), 
    name: str = Form(...), 
    password: str = Form(...), 
    confirm_password: str = Form(...), 
    email: str = Form(...), 
    role: str = Form(...,description="admin / staff"),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):

    if "sadmin" in roles:
        # Validasi panjang karakter dan tipe data
        
        if len(name) < 3 or len(password) < 6:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Name at least 3 characters and password at least 6 characters", "Output": ""})
        
        
        tenant_data = tenant_collection.find_one({"_id": ObjectId(tenantId)})
        if not tenant_data:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        input_timezone = tenant_data["timezone_name"]

        # Validasi alamat email menggunakan regular expression
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
        
        # Validasi konfirmasi password
        if password != confirm_password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
        
        existing_user = user_collection.find_one({"$or": [{"name": name}, {"email": email}]})
        if existing_user:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "name / email has been used", "Output": ""})
        
        hashed_password = pwd_context.hash(password)

        nama_tenant = get_nama_tenant(tenant_collection, tenantId)
        
        # Dapatkan timestamp saat ini dalam UTC
        current_time_utc = datetime.now(utc)

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

         # Validasi peran
        allowed_roles = ["staff", "admin"]
        if role.lower() not in allowed_roles:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": f"Invalid role. Only {', '.join(allowed_roles)} roles are allowed", "Output": ""})
    


        
        # Simpan data pengguna ke basis data
        new_user = {
            "name": name,
            "password": hashed_password,
            "email": email.lower(),
            "company_name": nama_tenant,
            "tenant_id": tenantId,
            "language": tenant_data["language"],
            "culture": tenant_data["culture"],
            "currency": tenant_data["currency"],
            "currency_position": tenant_data["currency_position"],
            "timestamp_create": localized_time,
            "timezone_name": input_timezone,
            "roles": role.lower(),
            "image": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCADIAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD6YoooqzEKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiihVYttVWZv7q0AFFadro8sg3Tnyh/d+81aEWk2adUZ/wDeNLmK5TnKK6j+zrL/AJ9kqGXSLN/uqyH/AGTRzBynO0Vp3WkTxqWgbzR/d6NWYysG2su1v7tMQUUUUCCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAfbwvNKIkXcWro9PsIrRN3DSfxPUejWf2a33uP3j9fatA1BokLRRRQUFFFFABVLULCK6T+7L/C9XaKAOPuI3hlaKVdpFMrotZtPtEG9B+8Tn6iudqjKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABVrS4fPvUjb7q/M1Va1vDifvpn9FVaQ4m7RRRUmoUUUUAFFFFABRRRQAVyuqQ+Reuq/db5lrqqwvEifv4X9VZaqJMjJooopmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVr+GjzMP8AdrIrQ0KTy73a3R1xSHE6OiiipNQooooAKKKKACiiigBO1YviQ/NCv+y1bXaud16TzL/b/cXFESZbGfRRRVmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAU6N2R1dfvK25abRQM6y0mWe3SVf4v0qY1zOlXptZdrbmib73t/tV0kTrIgdGDKehFQWmPooooKCiiigAoopkjqiF3baq9TQBHeXAt7d5W/h6e9cqzM7tI33mbc1WtVvWupdq8RL0qnVRMpSCiiimIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACrNjez2p+X5k/iQ1WooGdLa6jbT/KG2P8A3Xq91rjKljuJ4/uSyL/utS5RxkddxScVyv2+8/5+H/76qKSaeX/WSyN/vNRyhznRXWpWsGV373/upWHfXs903zNtT+FBVaijlFKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUU+GOWZ9kSM59q1rTR/4rh/8AgC0hmN95ttWYbC8k+7Ayj1b5a6O3toIFxFEq/hU9HMXynPx6NO335UX/AMeqZdF/vXH5JWzxRRdhaJkf2JH/AM/D/lTW0Nf4bj80rZ4o4qeYOVGBJo06/clRv/HaqzWF5H96BmHqvzV1VFVzBynGfdba1FdZcWsE4xLErH1xWXdaN/Fbv/wB/wD4qjmJ5THop80bwvsljZT/ALVMpkhRRRQAUUUUAFFFFABRRRQAUUUUAFXtN097n55Pli/vf3qdo9h9pbzZf9UP/Hq6FQqrgUuYqMRlvBFbx7IlCipaKKk0CiiigAooooAKKKKACiiigAooooAiuIIriPZKu4Vz+o6e9r+8T54vX+7XS01grDB6UEyjzHHUVoavYfZm82L/AFR/8drPqyAooooEFFFFABRRRQAVNZwNc3CRL/wI/wB1ahrc8PQBYnnI5Y4X6UmOJpxRrGgRBtVVwKkooqTUKKKKACiiigAooooAKKKKACiiigAooooAKKKKAI5Y1ljMbruVuDXLXkDW1w8Tfw/dP95a62sjxDDmJJ16rw3+7VRJkYdFFFMzCiiigAooooAK6jS12WEK/wCxmuXrrLL/AI84P9xf5UpFRJ6KKKk0CiiigAooooAKKKKACiiigAooooAKKKKACiiigAqpqq79PmX/AGM1bqC+/wCPOb/cagDk6KKKsyCiiigQUUUUAFdZZf8AHnB/uL/KuTrrLL/jzg/3F/lSkaRJ6KKKkoKKKKACiiigAooooAKKKKACiiigAooooAKKKKACoL3/AI85/wDcb+VT1Be/8ec/+438qAOToooqzIKKKKBBRRRQAV1ll/x5wf7i/wAqKKUjSJPRRRUlBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVBe/8AHnP/ALjfyoooA5OiiirMgooooEf/2Q=="
        }

        insert_result = user_collection.insert_one(new_user)
        projection = {"_id": False}
        result = user_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        
        return {"IsError": False, "Output": "Registration Successfully", "Data": result }
    
    if "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
        
            if len(name) < 3 or len(password) < 6:
                raise HTTPException(status_code=400, detail="Name at least 3 characters and password at least 6 characters")
            
            tenant_data = tenant_collection.find_one({"_id": ObjectId(tenant_id)})
            if not tenant_data:
                raise HTTPException(status_code=404, detail="Tenant not found")
            
            input_timezone = tenant_data["timezone_name"]

            # Validasi alamat email menggunakan regular expression
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
            
            # Validasi konfirmasi password
            if password != confirm_password:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
            
            existing_user = user_collection.find_one({"$or": [{"name": name}, {"email": email}]})
            if existing_user:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "name / email has been used", "Output": ""})
            
            hashed_password = pwd_context.hash(password)

            nama_tenant = get_nama_tenant(tenant_collection, tenant_id)
            
            # Dapatkan timestamp saat ini dalam UTC
            current_time_utc = datetime.now(utc)

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")
            
             # Validasi peran
            if role.lower() != "staff":
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid role. Only 'staff' role is allowed", "Output": ""})
    
            
            # Simpan data pengguna ke basis data
            new_user = {
                "name": name,
                "password": hashed_password,
                "email": email.lower(),
                "company_name": nama_tenant,
                "tenant_id": tenant_id,
                "language": tenant_data["language"],
                "culture": tenant_data["culture"],
                "currency": tenant_data["currency"],
                "currency_position": tenant_data["currency_position"],
                "timestamp_create": localized_time,
                "timezone_name": input_timezone,
                "roles": role.lower(),
                "image": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCADIAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD6YoooqzEKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiihVYttVWZv7q0AFFadro8sg3Tnyh/d+81aEWk2adUZ/wDeNLmK5TnKK6j+zrL/AJ9kqGXSLN/uqyH/AGTRzBynO0Vp3WkTxqWgbzR/d6NWYysG2su1v7tMQUUUUCCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAfbwvNKIkXcWro9PsIrRN3DSfxPUejWf2a33uP3j9fatA1BokLRRRQUFFFFABVLULCK6T+7L/C9XaKAOPuI3hlaKVdpFMrotZtPtEG9B+8Tn6iudqjKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABVrS4fPvUjb7q/M1Va1vDifvpn9FVaQ4m7RRRUmoUUUUAFFFFABRRRQAVyuqQ+Reuq/db5lrqqwvEifv4X9VZaqJMjJooopmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVr+GjzMP8AdrIrQ0KTy73a3R1xSHE6OiiipNQooooAKKKKACiiigBO1YviQ/NCv+y1bXaud16TzL/b/cXFESZbGfRRRVmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAU6N2R1dfvK25abRQM6y0mWe3SVf4v0qY1zOlXptZdrbmib73t/tV0kTrIgdGDKehFQWmPooooKCiiigAoopkjqiF3baq9TQBHeXAt7d5W/h6e9cqzM7tI33mbc1WtVvWupdq8RL0qnVRMpSCiiimIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACrNjez2p+X5k/iQ1WooGdLa6jbT/KG2P8A3Xq91rjKljuJ4/uSyL/utS5RxkddxScVyv2+8/5+H/76qKSaeX/WSyN/vNRyhznRXWpWsGV373/upWHfXs903zNtT+FBVaijlFKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUU+GOWZ9kSM59q1rTR/4rh/8AgC0hmN95ttWYbC8k+7Ayj1b5a6O3toIFxFEq/hU9HMXynPx6NO335UX/AMeqZdF/vXH5JWzxRRdhaJkf2JH/AM/D/lTW0Nf4bj80rZ4o4qeYOVGBJo06/clRv/HaqzWF5H96BmHqvzV1VFVzBynGfdba1FdZcWsE4xLErH1xWXdaN/Fbv/wB/wD4qjmJ5THop80bwvsljZT/ALVMpkhRRRQAUUUUAFFFFABRRRQAUUUUAFXtN097n55Pli/vf3qdo9h9pbzZf9UP/Hq6FQqrgUuYqMRlvBFbx7IlCipaKKk0CiiigAooooAKKKKACiiigAooooAiuIIriPZKu4Vz+o6e9r+8T54vX+7XS01grDB6UEyjzHHUVoavYfZm82L/AFR/8drPqyAooooEFFFFABRRRQAVNZwNc3CRL/wI/wB1ahrc8PQBYnnI5Y4X6UmOJpxRrGgRBtVVwKkooqTUKKKKACiiigAooooAKKKKACiiigAooooAKKKKAI5Y1ljMbruVuDXLXkDW1w8Tfw/dP95a62sjxDDmJJ16rw3+7VRJkYdFFFMzCiiigAooooAK6jS12WEK/wCxmuXrrLL/AI84P9xf5UpFRJ6KKKk0CiiigAooooAKKKKACiiigAooooAKKKKACiiigAqpqq79PmX/AGM1bqC+/wCPOb/cagDk6KKKsyCiiigQUUUUAFdZZf8AHnB/uL/KuTrrLL/jzg/3F/lSkaRJ6KKKkoKKKKACiiigAooooAKKKKACiiigAooooAKKKKACoL3/AI85/wDcb+VT1Be/8ec/+438qAOToooqzIKKKKBBRRRQAV1ll/x5wf7i/wAqKKUjSJPRRRUlBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVBe/8AHnP/ALjfyoooA5OiiirMgooooEf/2Q=="
            }

            insert_result = user_collection.insert_one(new_user)
            projection = {"_id": False}
            result = user_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)

            
            return {"IsError": False, "Output": "Registration Successfully", "Data": result }
        else:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "You do not have access to this company", "Output": ""})
    else:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "You do not have permission to access this endpoint", "Output": ""})

@app.post("/login", tags=["Akun"])
def login(email: str = Form(...), password: str = Form(...)):
    # Search for the email in staff collection
    user = user_collection.find_one({"email": email})

    # If the email is not found in staff collection, search in clients collection
    if user is None:
        user = clients_collection.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Incorrect email or password", "Output": ""})

        # Check the password if the email is found in clients collection
        if user["password"] != password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Incorrect email or password", "Output": ""})
        
        # Set roles to 'client' if the email is found in clients collection
        roles = "client"
    else:
        roles = "sadmin" if user["roles"] == "sadmin" else "admin" if user["roles"] == "admin" else "staff"

    # Additional handling for 'sadmin' roles
    if roles == "sadmin":
        company = " "
        tenant_id = " "
    else:
        company = user.get("company_name", "")
        if not company and roles != "client":
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "The company does not exist", "Output": ""})

        tenant_id = user.get("tenant_id", "")

    staff_name = user.get("name", "")
    if not staff_name:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Name does not exist", "Output": ""})

    # Verify hashed password for staff and admin roles
    if roles != "client":
        hashed_password = pwd_context.verify(password, user["password"])
        if not hashed_password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Incorrect email or password", "Output": ""})
    else:
        # For clients, compare the plain text password
        if user["password"] != password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Incorrect email or password", "Output": ""})

    token = generate_jwt_token(email, user["_id"], company, staff_name, tenant_id, roles)
        # Format respons sesuai keinginan
    token_str = token.decode("utf-8") if isinstance(token, bytes) else token

    # Format respons sesuai keinginan
    response_data = {
        "IsError": False,
        "Output": "Login Successfully",
        "Data": {"email": email, "roles": roles, "company": company, "tenant_id": tenant_id, "name": staff_name},
        "Token": token_str
    }
    return JSONResponse(content=response_data)


# Fungsi untuk membuat token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Fungsi untuk memverifikasi password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Fungsi untuk mendapatkan pengguna berdasarkan email
def get_user_by_email(email: str):
    user = user_collection.find_one({"email": email})  # Mengganti referensi ke user_collection
    return user

# Fungsi untuk membuat token pengaturan ulang kata sandi
def create_password_reset_token(email: str):
    expires = timedelta(hours=1)  # Waktu kadaluarsa token
    data = {"sub": email, "exp": datetime.utcnow() + expires}
    token = create_access_token(data)
    return token

# Fungsi untuk mengirim email verifikasi
def send_password_reset_email(email: str, token: str):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'bfcmochi@gmail.com'
    smtp_password = 'lwze onag hjup pszt'

    # Buat pesan email
    msg = MIMEMultipart()
    msg['From'] = 'bfcmochi@gmail.com'
    msg['To'] = email
    msg['Subject'] = 'Verifikasi Email'

    message = f"Click the following link to reset your password: http://127.0.0.1:8000/docs#/default/reset_password_handler_reset_password_post    token: {token}"

    msg.attach(MIMEText(message, 'plain'))
    

    # Kirim email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send verification email")
    

@app.post("/send-password-reset-email", tags=["Akun"])
def send_password_reset_email_handler(email: str = Form(...)):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "User Email not found", "Output": ""})
    token = create_password_reset_token(email)
    try:
        send_password_reset_email(email, token)
        return {"IsError": False, "Output": "Email Send"}
    except SMTPException:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Failed to send email", "Output": ""})

# Endpoint untuk mengatur ulang kata sandi
@app.post("/reset-password", tags=["Akun"])
def reset_password_handler(
    email: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    current_token: str = Depends(get_current_token)
):
    # Contoh jika token diterima sebagai string
    token_string = "your_token_string_here"
    bytes_token = token_string.encode('utf-8')  # Konversi menjadi bytes
    decoded_token = jwt.decode(bytes_token, SECRET_KEY, algorithms=[ALGORITHM])
    # Mendapatkan koleksi pengguna dari MongoDB
    user_collection = user_collection()

    # Mencari pengguna berdasarkan email
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User Email not found")

    # Memeriksa apakah password baru dan konfirmasi password cocok
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Password and confirmation password do not match")

    # Memeriksa apakah password baru sama dengan password lama
    if verify_password(new_password, user["password"]):
        raise HTTPException(status_code=400, detail="New password cannot be the same as the old password")

    # Mengubah password dan memperbarui koleksi MongoDB
    user["password"] = pwd_context.hash(new_password)
    user_collection.update_one({"email": email}, {"$set": {"password": user["password"]}})

    return {"IsError": False, "Output": "Password Reset Successfully"}

@app.post("/change-user-role", tags=["Akun"], dependencies=[Depends(get_current_user)])
def change_user_role(
    user_id: str,
    role: str = Form(..., description="admin or staff"),
    tenant_id: str = Depends(get_current_user_tenant_id),
    roles: str = Depends(get_current_user), perusahaan: str = Depends(get_current_user_perusahaan)):
    if "sadmin" in roles:
        guru_object_id = ObjectId(user_id)
        guru = user_collection.find_one({"_id": guru_object_id})

        if not guru:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "User not found", "Output": ""})

        # Perbarui field is_admin
        user_collection.update_one(
            {"_id": guru_object_id},
            {"$set": {"roles": role}}
        )
        
        # findGuru = user_collection.find_one({"_id": guru_object_id})
        # Buat respons sesuai dengan yang Anda inginkan
        nama_staff = guru["name"]
        if role == "staff":
            status_admin = "staff"
        elif role == "admin":
            status_admin = "admin"
        projection = {"_id": False}
        result = user_collection.find_one({"_id": guru_object_id}, projection=projection)
            
        message = f"User {nama_staff} Successfully changed to {status_admin} Roles"

        # return {"message": message}
        return {"IsError": False, "Output": message, "Data": result}
    elif "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            guru_object_id = ObjectId(user_id)
            guru = user_collection.find_one({"_id": guru_object_id, "tenant_id": perusahaan})

            if not guru:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "User not found", "Output": ""})

            # Perbarui field is_admin
            user_collection.update_one(
                {"_id": guru_object_id},
                {"$set": {"roles": role}}
            )
            
            projection = {"_id": False}
            result = user_collection.find_one({"_id": guru_object_id}, projection=projection)
            nama_guru = guru["name"]
            if role == "staff":
                status_admin = "staff"
            elif role == "admin":
                status_admin = "admin"
                
            message = f"Staff {nama_guru} Berhasil diubah menjadi Roles {status_admin}"

            # return {"message": message}
            return {"IsError": False, "Output": message, "Data": result}

    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/user-by-id", tags=["User"])
def get_user(    
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id),
    user_id: str = Depends(get_current_user_user_id)):

    if "sadmin" in roles:
        # Implementasi endpoint tanpa dependensi
        clients = list(user_collection.find({"_id": ObjectId(user_id)},{"password": 0}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_user_culture(user_id)
            timezone_name = get_user_timezone(user_id)
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["timestamp_create"], timezone_name
                )
                client["timestamp_create"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"User By Id: {user_id}", "Data": clients}

    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(user_collection.find({"_id": ObjectId(user_id)},{"password": 0}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_user_culture(user_id)
                timezone_name = get_user_timezone(user_id)
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_create"], timezone_name
                    )
                    client["timestamp_create"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"User By Id: {user_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/user-by-tenant", tags=["User"])
def get_all_user(    
    user_id: str = Depends(get_current_user_user_id),
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id),
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        # Check if tenantId is provided
        if tenantId:
            # Implementasi endpoint dengan dependensi tenantId
            clients = list(user_collection.find({"tenant_id": tenantId}, {"password": 0}))
        else:
            # Implementasi endpoint tanpa dependensi tenantId (retrieve all data)
            clients = list(user_collection.find({}, {"password": 0}))
        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_user_culture(user_id)
            timezone_name = get_user_timezone(user_id)
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["timestamp_create"], timezone_name
                )
                client["timestamp_create"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"User Data by TenantId: {tenantId}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(user_collection.find({"tenant_id": tenant_id},{"password": 0}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_user_culture(user_id)
                timezone_name = get_user_timezone(user_id)
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_create"], timezone_name
                    )
                    client["timestamp_create"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"User Data by TenantId: {tenant_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})



@app.put("/profile", tags=["User"], dependencies=[Depends(get_current_user)])
def update_profile_user(
    user_id: str = Depends(get_current_user_user_id), 
    image: UploadFile = File(None), 
    name: str = Form(None), 
    email: str = Form(None), 
    language: str = Form(None),
    culture: str = Form(None, description="example = en_US, id_ID"),
    input_timezone: str = Form(None),
    currency: str = Form(None),
    currency_position: bool = Form(None),
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):
    if "sadmin" in roles:
        # Cari entri profil berdasarkan ID
        existing_profil = user_collection.find_one({"_id": ObjectId(user_id)})

        if not existing_profil:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "User not found", "Output": ""})
        
        current_time_utc = datetime.now(utc)

        # Ambil zona waktu dari data sebelumnya jika input_timezone kosong
        if not input_timezone:
            input_timezone = existing_profil.get("timezone_name", "UTC")

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

        update_data = {}
        if name is not None and name != "":
            update_data["name"] = name
        if email is not None and email != "":
            update_data["email"] = email
        if language is not None:
            update_data["language"] = language
        if culture is not None:
            update_data["culture"] = culture.replace("-", "_")
        if currency is not None:
            currency_symbol = currency.replace(" ", "").split("-")[0].strip()
            update_data["currency"] = currency_symbol
        if currency_position is not None:
            update_data["currency_position"] = currency_position

        update_data["timestamp_update"] = localized_time  # Update timestamp
          # Update zona waktu
        update_data["timezone_name"] = input_timezone
        
        # Periksa apakah ada foto baru yang diunggah
        if image and image.file:
            # Baca data gambar
            image_data = image.file.read()

            # Proses gambar menggunakan Pillow
            img = Image.open(BytesIO(image_data))

            # Resize gambar menjadi 300x300
            img.thumbnail((300, 300))

            # Kompres gambar menjadi berukuran di bawah 1MB
            img = img.convert("RGB")
            output_buffer = BytesIO()
            img.save(output_buffer, format="JPEG", quality=85)
            image_data = output_buffer.getvalue()
            
            # Set bidang image dalam update_data
            update_data["image"] = base64.b64encode(image_data).decode()
        
        # Buat salinan dari dokumen guru
        updated_guru = existing_profil.copy()
        updated_guru.update(update_data)

        user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": updated_guru})

        projection = {"_id": False}
        result = user_collection.find_one({"_id": ObjectId(user_id)}, projection=projection)

        return {"IsError": False, "Output": "Profil updated Successfully", "Data": result}
    
    if "staff" in roles or "admin" in roles:
        if tenant_id == perusahaan:
            existing_profil = user_collection.find_one({"_id": ObjectId(user_id)})

            if not existing_profil:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "User not found", "Output": ""})
            
            current_time_utc = datetime.now(utc)

            if not input_timezone:
                input_timezone = existing_profil.get("timezone_name", "UTC")

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

            update_data = {}
            if name is not None and name != "":
                update_data["name"] = name
            if email is not None and email != "":
                update_data["email"] = email
            if language is not None:
                update_data["language"] = language
            if culture is not None:
                update_data["culture"] = culture.replace("-", "_")
            if currency is not None:
                currency_symbol = currency.replace(" ", "").split("-")[0].strip()
                update_data["currency"] = currency_symbol
            if currency_position is not None:
                update_data["currency_position"] = currency_position

            update_data["timestamp_update"] = localized_time
            update_data["timezone_name"] = input_timezone
            
            if image and image.file:
                # Baca data gambar
                image_data = image.file.read()

                # Proses gambar menggunakan Pillow
                img = Image.open(BytesIO(image_data))

                # Resize gambar menjadi 300x300
                img.thumbnail((300, 300))

                # Kompres gambar menjadi berukuran di bawah 1MB
                img = img.convert("RGB")
                output_buffer = BytesIO()
                img.save(output_buffer, format="JPEG", quality=85)
                image_data = output_buffer.getvalue()
                
                # Set bidang image dalam update_data
                update_data["image"] = base64.b64encode(image_data).decode()
            
            # Buat salinan dari dokumen guru
            updated_guru = existing_profil.copy()
            updated_guru.update(update_data)

            user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": updated_guru})
            
            projection = {"_id": False}
            result = user_collection.find_one({"_id": ObjectId(user_id)}, projection=projection)

            return {"IsError": False, "Output": "Profil updated Successfully", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access to this company", "Output": ""})

    else:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.delete("/user-delete", tags=["User"], dependencies=[Depends(get_current_user)])
def delete_user(user_id: str, 
    roles: str = Depends(get_current_user),    
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):
    if "sadmin" in roles:
        
        obj_id = ObjectId(user_id)

        clients = user_collection.find_one({"_id": obj_id})
        if clients is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
        
        user_collection.delete_one({"_id": obj_id})
        return {"IsError": False, "Output": "User Successfully deleted"}
    
    if "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(user_id)
            # Now you can use the decoded "id" parameter in your database query
            clients = user_collection.find_one({"_id": obj_id, "tenant_id": perusahaan})
            if clients is None:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
            
            user_collection.delete_one({"_id": obj_id, "tenant_id": perusahaan})
            return {"IsError": False, "Output": "User Successfully deleted"}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permission for this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/history", tags=["History"])
def get_history(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(history_collection.find({"campaign_id": campaign_id, "tenant_id": tenantId}))

        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_update" in client:
                if "." in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  

        return {"IsError": False, "Output": f"Metrics Data by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles or "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(history_collection.find({"campaign_id": campaign_id, "tenant_id": tenant_id}))

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  
                    
            return {"IsError": False, "Output": f"Metrics Data by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


# metrics
@app.post("/metrics-create", tags=["Metrics"])
def create_metrics(
    campaign_id: str,
    clicks: int = Form(..., description="150000"),
    lpview: int = Form(..., description="clicks > '95000'"),
    catc: int = Form(..., description="lpview > '25000'"),
    ctview: int = Form(..., description="10000"),
    results: int = Form(..., description="750"),
    amountspent: int = Form(..., description="4500000"),
    reach: int = Form(..., description="97000"),
    impressions: int = Form(..., description="230000"),
    delivery: float = Form(..., description="85"),
    leads: int = Form(..., description="220"),
    purchase: int = Form(..., description="7500000"),
    cpc: float = Form(..., description="3000"),
    frequency: float = Form(..., description="Impressions/Reach"),
    ctr: float = Form(..., description="(Link Click/impressions)"),
    # oclp: float = Form(..., description="30.5"),
    cpr: int = Form(..., description="Amount Spent/Result"),
    cpm: int = Form(..., description="amountspent/(impressions/1000)"),
    roas: float = Form(..., description="purchase/amountspent"),
    # realroas: float = Form(..., description="3.1"),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None,description="Hanya Untuk SuperAdmin" )):
    if "sadmin" in roles:
        # Cari campaign_id dalam koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        if not campaign_data:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        metrics_data = metrics_collection.find_one({"campaign_id": campaign_id})
        if metrics_data:
            raise HTTPException(status_code=404, detail="Campaigns already in use")
        
        input_timezone = campaign_data["timezone_name"]

        tenant_data = tenant_collection.find_one({"_id": ObjectId(tenantId)})
        if not tenant_data:
            raise HTTPException(status_code=404, detail="Tenant not found")

        nama_tenant = get_nama_tenant(tenant_collection, tenantId)

        current_time_utc = datetime.now(utc)

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

        # Hitung frequency
        frequency_value = impressions/reach
        rounded_frequency = round(frequency_value, 1)  # Membulatkan ke satu angka dibelakang koma

        # Hitung rar, cpc, ctr, oclp, cpr, atc, roas, dan realroas
        rar = (reach / amountspent)
        rounded_rar = round(rar, 1)

        oclp = (lpview / clicks) * 100
        rounded_oclp = round(oclp, 1)

        rroas = purchase / amountspent
        rounded_rroas = round(rroas, 1)

        ratc = (catc / lpview) * 100
        rounded_atc = round(ratc, 1)

        data_to_insert = {
            "campaign_id": campaign_id,
            "client_id": campaign_data["client_id"],
            "account_id": campaign_data["account_id"],
            "clicks": clicks,
            "lpview": lpview,
            "ctview": ctview,
            "results": results,
            "amountspent": amountspent,
            "reach": reach,
            "impressions": impressions,
            "purchase": purchase,
            "delivery": delivery,
            "frequency": frequency,
            "rar": rounded_rar,
            "cpc": cpc,
            "ctr": ctr,
            "oclp": rounded_oclp,
            "cpr": cpr,
            "leads": leads,
            "cpm": cpm,
            "atc": rounded_atc,
            "roas": roas,
            "realroas": rounded_rroas,
            "company_name": nama_tenant,
            "tenant_id": tenantId,
            "timestamp_create": localized_time,
        }

        # Tambahkan dokumen ke koleksi "metrics" di MongoDB
        insert_result = metrics_collection.insert_one(data_to_insert)
        projection = {"_id": False}
        result = metrics_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        new_metric_id = str(insert_result.inserted_id)

        # Generate ID metrics
        id_metrics = new_metric_id

        # Buat dokumen untuk koleksi "settings"
        settings_data = {
            "campaign_id": campaign_id,
            "client_id": campaign_data["client_id"],
            "account_id": campaign_data["account_id"],
            "metrics_id": id_metrics,
            "rar": 5.0,
            "ctr": 1.5,
            "oclp": 80.0,
            "roas": 3.0,
            "cpr": 5000,
            "cpc": 1000,
            "company_name": nama_tenant,
            "tenant_id": tenantId,
        }

        # Tambahkan dokumen ke koleksi "settings"
        settings_collection.insert_one(settings_data)

        return {"IsError": False, "Output": "Create Metrics Successfully", "Data": result }

    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Cari campaign_id dalam koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            if not campaign_data:
                raise HTTPException(status_code=404, detail="Campaign not found")
        
            metrics_data = metrics_collection.find_one({"campaign_id": campaign_id})
            if metrics_data:
                raise HTTPException(status_code=404, detail="Campaigns already in use")

            input_timezone = campaign_data["timezone_name"]

            tenant_data = tenant_collection.find_one({"_id": ObjectId(tenant_id)})
            if not tenant_data:
                raise HTTPException(status_code=404, detail="Tenant not found")
            
            nama_tenant = get_nama_tenant(tenant_collection, tenant_id)

            current_time_utc = datetime.now(utc)

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

            # Hitung rar, cpc, ctr, oclp, cpr, atc, roas, dan realroas
            rar = (reach / amountspent) 
            rounded_rar = round(rar, 1)

            oclp = (lpview / clicks) * 100
            rounded_oclp = round(oclp, 1)

            rroas = purchase / amountspent
            rounded_rroas = round(rroas, 1)

            ratc = (catc / lpview) * 100
            rounded_atc = round(ratc, 1)

            data_to_insert = {
                "campaign_id": campaign_id,
                "client_id": campaign_data["client_id"],
                "account_id": campaign_data["account_id"],
                "clicks": clicks,
                "lpview": lpview,
                "ctview": ctview,
                "results": results,
                "amountspent": amountspent,
                "reach": reach,
                "impressions": impressions,
                "purchase": purchase,
                "delivery": delivery,
                "frequency": frequency,
                "rar": rounded_rar,
                "cpc": cpc,
                "ctr": ctr,
                "oclp": rounded_oclp,
                "cpr": cpr,
                "leads": leads,
                "cpm": cpm,
                "atc": rounded_atc,
                "roas": roas,
                "realroas": rounded_rroas,
                "company_name": nama_tenant,
                "tenant_id": tenantId,
                "timestamp_create": localized_time,
            }

            # Tambahkan dokumen ke koleksi "metrics" di MongoDB
            insert_result = metrics_collection.insert_one(data_to_insert)
            projection = {"_id": False}
            result = metrics_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
            new_metric_id = str(insert_result.inserted_id)

            # Generate ID metrics
            id_metrics = new_metric_id

            # Buat dokumen untuk koleksi "settings"
            settings_data = {
                "campaign_id": campaign_id,
                "client_id": campaign_data["client_id"],
                "account_id": campaign_data["account_id"],
                "metrics_id": id_metrics,
                "rar": 5.0,
                "ctr": 1.5,
                "oclp": 80.0,
                "roas": 3.0,
                "cpr": 5000,
                "cpc": 1000,
                "company_name": nama_tenant,
                "tenant_id": tenant_id,
            }

            # Tambahkan dokumen ke koleksi "settings"
            settings_collection.insert_one(settings_data)

            return {"IsError": False, "Output": "Create Metrics Successfully", "Data": result }

        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.put("/metrics-edit", tags=["Metrics"])
def edit_metrics(
    campaign_id: str,
    clicks: int = Form(..., description="150000"),
    lpview: int = Form(..., description="clicks > '95000'"),
    catc: int = Form(..., description="lpview > '25000'"),
    ctview: int = Form(..., description="10000"),
    results: int = Form(..., description="750"),
    amountspent: int = Form(..., description="4500000"),
    reach: int = Form(..., description="97000"),
    impressions: int = Form(..., description="230000"),
    delivery: float = Form(..., description="85"),
    leads: int = Form(..., description="220"),
    purchase: int = Form(..., description="7500000"),
    cpc: float = Form(..., description="3000"),
    frequency: float = Form(..., description="Impressions/Reach"),
    ctr: float = Form(..., description="(Link Click/impressions)"),
    # oclp: float = Form(..., description="30.5"),
    cpr: int = Form(..., description="Amount Spent/Result"),
    cpm: int = Form(..., description="amountspent/(impressions/1000)"),
    roas: float = Form(..., description="purchase/amountspent"),
    # realroas: float = Form(..., description="3.1"),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)
):
    if "sadmin" in roles:
        campaign_metrics = metrics_collection.find_one({"campaign_id": campaign_id})
        if not campaign_metrics:
            raise HTTPException(status_code=404, detail="Campaign & Metrics not found")
        
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        if not campaign_data:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        input_timezone = campaign_data["timezone_name"]

        current_time_utc = datetime.now(utc)

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

        # Hitung rar, cpc, ctr, oclp, cpr, atc, roas, dan realroas
        rar = (reach / amountspent) 
        rounded_rar = round(rar, 1)

        oclp = (lpview / clicks) * 100
        rounded_oclp = round(oclp, 1)

        rroas = purchase / amountspent
        rounded_rroas = round(rroas, 1)

        ratc = (catc / lpview) * 100
        rounded_atc = round(ratc, 1)

        updated_data = {
            "clicks": clicks,
            "lpview": lpview,
            "ctview": ctview,
            "results": results,
            "amountspent": amountspent,
            "reach": reach,
            "impressions": impressions,
            "purchase": purchase,
            "delivery": delivery,
            "frequency": frequency,
            "rar": rounded_rar,
            "cpc": cpc,
            "ctr": ctr,
            "oclp": rounded_oclp,
            "cpr": cpr,
            "leads": leads,
            "cpm": cpm,
            "atc": rounded_atc,
            "roas": roas,
            "realroas": rounded_rroas,
            "company_name": campaign_data["company_name"],
            "tenant_id": campaign_data["tenant_id"],
            "client_id": campaign_data["client_id"],
            "account_id": campaign_data["account_id"]
        }
        updated_data["timestamp_update"] = localized_time


        if updated_data:
            metrics_collection.update_one({"campaign_id": campaign_id}, {"$set": updated_data})
            projection = {"_id": False}
            result = metrics_collection.find_one({"campaign_id": campaign_id}, projection=projection)

        history_data = {
            "campaign_id": campaign_id,
            "clicks": clicks,
            "lpview": lpview,
            "ctview": ctview,
            "results": results,
            "amountspent": amountspent,
            "reach": reach,
            "impressions": impressions,
            "purchase": purchase,
            "delivery": delivery,
            "frequency": frequency,
            "rar": rounded_rar,
            "cpc": cpc,
            "ctr": ctr,
            "oclp": rounded_oclp,
            "cpr": cpr,
            "leads": leads,
            "cpm": cpm,
            "atc": rounded_atc,
            "roas": roas,
            "realroas": rounded_rroas,
            "company_name": campaign_data["company_name"],
            "tenant_id": campaign_data["tenant_id"],
            "client_id": campaign_data["client_id"],
            "account_id": campaign_data["account_id"]
        }
        history_data["timestamp_update"] = localized_time

        history_collection.insert_one(history_data)

        return {"IsError": False, "Output": "Metrics Successfully edited", "Data": result}
    
    if "admin" in roles or "staff" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            campaign_metrics = metrics_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if not campaign_metrics:
                raise HTTPException(status_code=404, detail="Campaign & Metrics not found")
            
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            if not campaign_data:
                raise HTTPException(status_code=404, detail="Campaign not found")
            
            input_timezone = campaign_data["timezone_name"]

            current_time_utc = datetime.now(utc)

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

            # Hitung rar, cpc, ctr, oclp, cpr, atc, roas, dan realroas
            rar = (reach / amountspent) 
            rounded_rar = round(rar, 1)

            oclp = (lpview / clicks) * 100
            rounded_oclp = round(oclp, 1)

            rroas = purchase / amountspent
            rounded_rroas = round(rroas, 1)

            ratc = (catc / lpview) * 100
            rounded_atc = round(ratc, 1)

            updated_data = {
                "clicks": clicks,
                "lpview": lpview,
                "ctview": ctview,
                "results": results,
                "amountspent": amountspent,
                "reach": reach,
                "impressions": impressions,
                "purchase": purchase,
                "delivery": delivery,
                "frequency": frequency,
                "rar": rounded_rar,
                "cpc": cpc,
                "ctr": ctr,
                "oclp": rounded_oclp,
                "cpr": cpr,
                "leads": leads,
                "cpm": cpm,
                "atc": rounded_atc,
                "roas": roas,
                "realroas": rounded_rroas,
                "company_name": campaign_data["company_name"],
                "tenant_id": campaign_data["tenant_id"],
                "client_id": campaign_data["client_id"],
                "account_id": campaign_data["account_id"]
            }
            updated_data["timestamp_update"] = localized_time


            if updated_data:
                metrics_collection.update_one({"campaign_id": campaign_id}, {"$set": updated_data})
                projection = {"_id": False}
                result = metrics_collection.find_one({"campaign_id": campaign_id}, projection=projection)

            history_data = {
                "campaign_id": campaign_id,
                "clicks": clicks,
                "lpview": lpview,
                "ctview": ctview,
                "results": results,
                "amountspent": amountspent,
                "reach": reach,
                "impressions": impressions,
                "purchase": purchase,
                "delivery": delivery,
                "frequency": frequency,
                "rar": rounded_rar,
                "cpc": cpc,
                "ctr": ctr,
                "oclp": rounded_oclp,
                "cpr": cpr,
                "leads": leads,
                "cpm": cpm,
                "atc": rounded_atc,
                "roas": roas,
                "realroas": rounded_rroas,
                "company_name": campaign_data["company_name"],
                "tenant_id": campaign_data["tenant_id"],
                "client_id": campaign_data["client_id"],
                "account_id": campaign_data["account_id"]
            }
            history_data["timestamp_update"] = localized_time

            history_collection.insert_one(history_data)

            return {"IsError": False, "Output": "Metrics Successfully edited", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/metric-by-campaign-id", tags=["Metrics"])
def get_metrics(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(metrics_collection.find({"campaign_id": campaign_id, "tenant_id": tenantId}))

        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            if culture and timezone_name:
                client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_create" in client:
                if "." in client["timestamp_create"]:
                    client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_create"]:
                    client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

            if "timestamp_update" in client:
                if "." in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]


        return {"IsError": False, "Output": f"Metrics Data by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(metrics_collection.find({"campaign_id": campaign_id, "tenant_id": tenant_id}))

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                if culture and timezone_name:
                    client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_create" in client:
                    if "." in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]   
                    
            return {"IsError": False, "Output": f"Metrics Data by CampaignId: {campaign_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(metrics_collection.find({"campaign_id": campaign_id, "tenant_id": tenant_id, "client_id": user_id}))

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                if culture and timezone_name:
                    client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_create" in client:
                    if "." in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]   
                    
            return {"IsError": False, "Output": f"Metrics Data by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})
    
#PR NIH BOS
@app.get("/metric-by-tenant-id", tags=["Metrics"])
def get_metrics_by_tenant(
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(metrics_collection.find({"tenant_id": tenantId}))

        # Inisialisasi list untuk menyimpan data yang akan dikembalikan
        formatted_clients = []

        for client in clients:
            campaignId = client.get("campaign_id")

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaignId)})
            cam_name = campaign_data.get("name", "")
            cam_status = campaign_data.get("status", "")
            cam_platform = campaign_data.get("platform", "")
            start_date = campaign_data.get("start_date", "")
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaignId)
            timezone_name = get_campaign_timezone(campaignId)
            
            if culture and timezone_name:
                client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Ubah format start_date sesuai culture dan timezone
            start_date = format_timestamp(start_date, culture, timezone_name)

            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_create" in client:
                if "." in client["timestamp_create"]:
                    client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_create"]:
                    client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

            if "timestamp_update" in client:
                if "." in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  

            if "." in start_date:
                start_date = start_date.rsplit('.', 1)[0]
            elif ":" in start_date:
                start_date = start_date.rsplit(':', 1)[0]

            # Tambahkan data yang telah diolah ke dalam list formatted_clients
            formatted_clients.append({
                "campaign_name": cam_name,
                "campaign_status": cam_status,
                "campaign_platform": cam_platform,
                "start_date": start_date,
                **client  # Tambahkan semua data client yang telah diolah sebelumnya
            })

        return {"IsError": False, "Output": f"Metrics Data by TenantId: {tenantId}", "Data": formatted_clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(metrics_collection.find({"tenant_id": tenant_id}))

            # Inisialisasi list untuk menyimpan data yang akan dikembalikan
            formatted_clients = []

            for client in clients:
                campaignId = client.get("campaign_id")

                # Mengambil nilai currency dan currency_position dari koleksi campaigns
                campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaignId)})
                print(campaign_data)
                cam_name = campaign_data["name"]
                cam_status = campaign_data.get("status", "")
                cam_platform = campaign_data.get("platform", "")
                start_date = campaign_data.get("start_date", "")
                currency = campaign_data.get("currency", "")
                currency_position = campaign_data.get("currency_position", True)

                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaignId)
                timezone_name = get_campaign_timezone(campaignId)
                
                if culture and timezone_name:
                    client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Ubah format start_date sesuai culture dan timezone
                start_date = format_timestamp(start_date, culture, timezone_name)

                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_create" in client:
                    if "." in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  

                if "." in start_date:
                    start_date = start_date.rsplit('.', 1)[0]
                elif ":" in start_date:
                    start_date = start_date.rsplit(':', 1)[0]

                # Tambahkan data yang telah diolah ke dalam list formatted_clients
                formatted_clients.append({
                    "campaign_name": cam_name,
                    "campaign_status": cam_status,
                    "campaign_platform": cam_platform,
                    "start_date": start_date,
                    **client  # Tambahkan semua data client yang telah diolah sebelumnya
                })

            return {"IsError": False, "Output": f"Metrics Data by TenantId: {tenant_id}", "Data": formatted_clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(metrics_collection.find({"tenant_id": tenant_id, "client_id": user_id}))

            # Inisialisasi list untuk menyimpan data yang akan dikembalikan
            formatted_clients = []

            for client in clients:
                campaignId = client.get("campaign_id")

                # Mengambil nilai currency dan currency_position dari koleksi campaigns
                campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaignId)})
                cam_name = campaign_data.get("name", "")
                cam_status = campaign_data.get("status", "")
                cam_platform = campaign_data.get("platform", "")
                start_date = campaign_data.get("start_date", "")
                currency = campaign_data.get("currency", "")
                currency_position = campaign_data.get("currency_position", True)

                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaignId)
                timezone_name = get_campaign_timezone(campaignId)
                
                if culture and timezone_name:
                    client["timestamp_create"] = format_timestamp(client["timestamp_create"], culture, timezone_name)
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Ubah format start_date sesuai culture dan timezone
                start_date = format_timestamp(start_date, culture, timezone_name)

                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_create" in client:
                    if "." in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_create"]:
                        client["timestamp_create"] = client["timestamp_create"].rsplit(':', 1)[0]

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  

                if "." in start_date:
                    start_date = start_date.rsplit('.', 1)[0]
                elif ":" in start_date:
                    start_date = start_date.rsplit(':', 1)[0]

                # Tambahkan data yang telah diolah ke dalam list formatted_clients
                formatted_clients.append({
                    "campaign_name": cam_name,
                    "campaign_status": cam_status,
                    "campaign_platform": cam_platform,
                    "start_date": start_date,
                    **client  # Tambahkan semua data client yang telah diolah sebelumnya
                })

            return {"IsError": False, "Output": f"Metrics Data by TenantId: {tenant_id}", "Data": formatted_clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/metrics-7", tags=["Metrics"])
def metrics_7(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(history_collection.find(
            {"campaign_id": campaign_id, "tenant_id": tenantId},
            sort=[("timestamp_update", DESCENDING)],
            limit=7
        ))

        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_update" in client:
                if "." in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                elif ":" in client["timestamp_update"]:
                    client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  

        total_count = len(clients)

        return {
            "IsError": False,
            "Output": f"7 Last Metrics Data by CampaignId: {campaign_id}",
            "Total": total_count,
            "Data": clients
        }
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "tenant_id": tenant_id},
                sort=[("timestamp_update", DESCENDING)],
                limit=7
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  
                    
            total_count = len(clients)

            return {
                "IsError": False,
                "Output": f"7 Last Metrics Data by CampaignId: {campaign_id}",
                "Total": total_count,
                "Data": clients
            }
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "client_id": user_id, "tenant_id": tenant_id},
                sort=[("timestamp_update", DESCENDING)],
                limit=7
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    if "." in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    elif ":" in client["timestamp_update"]:
                        client["timestamp_update"] = client["timestamp_update"].rsplit(':', 1)[0]  
                    
            total_count = len(clients)

            return {
                "IsError": False,
                "Output": f"7 Last Metrics Data by CampaignId: {campaign_id}",
                "Total": total_count,
                "Data": clients
            }
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/metrics-settings-by", tags=["Metrics Settings"])
def metrics_settings_by(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(settings_collection.find({"campaign_id": campaign_id,"tenant_id": tenantId}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Metrics Settings Data by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(settings_collection.find({"campaign_id": campaign_id,"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Metrics Settings Data by CampaignId: {campaign_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(settings_collection.find({"campaign_id": campaign_id,"tenant_id": tenant_id, "client_id": user_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Metrics Settings Data by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.put("/metrics-settings", tags=["Metrics Settings"])
def settings_metrics(
    campaign_id: str,
    rar: float = Form(None, description="Reach Amount Ratio (RAR), Recommended value > 5%"),
    ctr: float = Form(None, description="Click-Through Rate (CTR), Recommended value > 1,5%"),
    oclp: float = Form(None, description="Optimized Cost per Landing Page View (OCLP), Recommended value > 80%"),
    roas: float = Form(None, description="Return on Ad Spend (ROAS), Recommended value > 3.0x"),
    cpr: int = Form(None, description="Cost per Result (CPR), Recommended value < Rp 5.000"),
    cpc: int = Form(None, description="Cost Per Click (CPC), Recommended value < Rp 1.000"),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)
):
    if "sadmin" in roles:
        # Periksa apakah campaign_id ada dalam koleksi "settings"
        existing_settings_data = settings_collection.find_one({"campaign_id": campaign_id})
        if existing_settings_data is None:
            raise HTTPException(status_code=404, detail="campaign not found")

        update_data = {}
        if rar is not None:
            update_data["rar"] = rar
        if ctr is not None:
            update_data["ctr"] = ctr
        if oclp is not None:
            update_data["oclp"] = oclp
        if roas is not None:
            update_data["roas"] = roas
        if cpr is not None:
            update_data["cpr"] = cpr
        if cpc is not None:
            update_data["cpc"] = cpc

        update_data["company_name"] = existing_settings_data["company_name"]
        update_data["tenant_id"] = existing_settings_data["tenant_id"]

        if update_data:
            settings_collection.update_one({"campaign_id": campaign_id}, {"$set": update_data})
            projection = {"_id": False}
            result = settings_collection.find_one({"campaign_id": campaign_id}, projection=projection)

        return {"IsError": False, "Output": "Metrics Settings Successfully edited", "Data": result}
    
    if "admin" in roles or "staff" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Periksa apakah campaign_id ada dalam koleksi "settings"
            existing_settings_data = settings_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if existing_settings_data is None:
                raise HTTPException(status_code=404, detail="campaign not found")

            update_data = {}
            if rar is not None:
                update_data["rar"] = rar
            if ctr is not None:
                update_data["ctr"] = ctr
            if oclp is not None:
                update_data["oclp"] = oclp
            if roas is not None:
                update_data["roas"] = roas
            if cpr is not None:
                update_data["cpr"] = cpr
            if cpc is not None:
                update_data["cpc"] = cpc

            update_data["company_name"] = existing_settings_data["company_name"]
            update_data["tenant_id"] = existing_settings_data["tenant_id"]

            if update_data:
                settings_collection.update_one({"campaign_id": campaign_id}, {"$set": update_data})
                projection = {"_id": False}
                result = settings_collection.find_one({"campaign_id": campaign_id}, projection=projection)

            return {"IsError": False, "Output": "Metrics Settings Successfully edited", "Data": result}

        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/suggestions", tags=["Suggestions"])
def get_suggestions(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:

        # Membaca data dari file suggestions.json
        with open('suggestions.json', 'r') as json_file:
            existing_json_data = json.load(json_file)
        # Periksa apakah campaign_id ada dalam koleksi "settings"
        existing_settings_data = settings_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenantId})
        if existing_settings_data is None:
            raise HTTPException(status_code=404, detail="campaign not found in the settings collections")

        # Periksa apakah id_metrics ada dalam koleksi "metrics"
        existing_metrics_data = metrics_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenantId})
        if existing_metrics_data is None:
            raise HTTPException(status_code=404, detail="campaign not found in the metrics collections")

        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        culture = get_campaign_culture(campaign_id)
        # Ambil nilai 'rar' dari koleksi "metrics"
        rar_metrics = existing_metrics_data.get("rar", "")

        # Ambil nilai 'rar' dari koleksi "settings"
        rar_settings = existing_settings_data.get("rar", "")

        # Ambil nilai 'cpc' dari koleksi "metrics"
        cpc_metrics = existing_metrics_data.get("cpc", "")

        # Ambil nilai 'cpc' dari koleksi "settings"
        cpc_settings = existing_settings_data.get("cpc", "")

        # Ambil nilai 'ctr' dari koleksi "metrics"
        ctr_metrics = existing_metrics_data.get("ctr", "")

        # Ambil nilai 'ctr' dari koleksi "settings"
        ctr_settings = existing_settings_data.get("ctr", "")

        # Ambil nilai 'oclp' dari koleksi "metrics"
        oclp_metrics = existing_metrics_data.get("oclp", "")

        # Ambil nilai 'oclp' dari koleksi "settings"
        oclp_settings = existing_settings_data.get("oclp", "")

        # Ambil nilai 'cpr' dari koleksi "metrics"
        cpr_metrics = existing_metrics_data.get("cpr", "")

        # Ambil nilai 'cpr' dari koleksi "settings"
        cpr_settings = existing_settings_data.get("cpr", "")

        # Ambil nilai 'roas' dari koleksi "metrics"
        roas_metrics = existing_metrics_data.get("roas", "")

        # Ambil nilai 'roas' dari koleksi "settings"
        roas_settings = existing_settings_data.get("roas", "")

        suggestions = []

        if float(rar_metrics) > float(rar_settings):
            suggestion_type = "Success"
            color = "Success"

        elif float(rar_metrics) == float(rar_settings):
            suggestion_type = "Warning"
            color = "Warning"

        else: 
            suggestion_type = "Danger"
            color = "Warning"

            rar_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    rar_entry = entry[culture].get("RAR", {}).get(suggestion_type, {})
                    break

            if rar_entry is not None:
                rar_title = rar_entry.get("Title", "")
                rar_msg = rar_entry.get("Message", "")
                rar_new = rar_entry.get("message", "")

                response_data = {
                    "rar": {
                        "id" : 1,
                        "title": rar_title,
                        "msg": rar_msg,
                        "color": color,
                        "value": rar_metrics,
                        "target": rar_settings,
                        "massage": rar_new
                    }
                }

                suggestions.append(response_data)

        if oclp_metrics and oclp_settings:
            if float(oclp_metrics) > float(oclp_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(oclp_metrics) == float(oclp_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            oclp_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    oclp_entry = entry[culture].get("OCLP", {}).get(suggestion_type, {})
                    break

            if oclp_entry is not None:
                oclp_title = oclp_entry.get("Title", "")
                oclp_msg = oclp_entry.get("Message", "")
                oclp_new = oclp_entry.get("message", "")

                response_data = {
                    "oclp": {
                        "id" : 2,
                        "title": oclp_title,
                        "msg": oclp_msg,
                        "color": color,
                        "value": oclp_metrics,
                        "target": oclp_settings,
                        "massage": oclp_new
                    }
                }

                suggestions.append(response_data)

        if ctr_metrics and ctr_settings:
            if float(ctr_metrics) > float(ctr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(ctr_metrics) == float(ctr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            ctr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    ctr_entry = entry[culture].get("CTR", {}).get(suggestion_type, {})
                    break

            if ctr_entry is not None:
                ctr_title = ctr_entry.get("Title", "")
                ctr_msg = ctr_entry.get("Message", "")
                ctr_new = ctr_entry.get("message", "")

                response_data = {
                    "ctr": {
                        "id" : 3,
                        "title": ctr_title,
                        "msg": ctr_msg,
                        "color": color,
                        "value": ctr_metrics,
                        "target": ctr_settings,
                        "massage": ctr_new
                    }
                }

                suggestions.append(response_data)

        if roas_metrics and roas_settings:
            if float(roas_metrics) > float(roas_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(roas_metrics) == float(roas_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            roas_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    roas_entry = entry[culture].get("ROAS", {}).get(suggestion_type, {})
                    break

            if roas_entry is not None:
                roas_title = roas_entry.get("Title", "")
                roas_msg = roas_entry.get("Message", "")
                roas_new = roas_entry.get("message", "")

                response_data = {
                    "roas": {
                        "id" : 4,
                        "title": roas_title,
                        "msg": roas_msg,
                        "color": color,
                        "value": roas_metrics,
                        "target": roas_settings,
                        "massage": roas_new
                    }
                }

                suggestions.append(response_data)

        if cpr_metrics and cpr_settings:
            if float(cpr_metrics) < float(cpr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpr_metrics) == float(cpr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpr_entry = entry[culture].get("CPR", {}).get(suggestion_type, {})
                    break

            if cpr_entry is not None:
                cpr_title = cpr_entry.get("Title", "")
                cpr_msg = cpr_entry.get("Message", "")
                cpr_new = cpr_entry.get("message", "")

                response_data = {
                    "cpr": {
                        "id" : 5,
                        "title": cpr_title,
                        "msg": cpr_msg,
                        "color": color,
                        "value": cpr_metrics,
                        "target": cpr_settings,
                        "massage": cpr_new
                    }
                }

                suggestions.append(response_data)

        if cpc_metrics and cpc_settings:
            if float(cpc_metrics) < float(cpc_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpc_metrics) == float(cpc_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpc_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpc_entry = entry[culture].get("CPC", {}).get(suggestion_type, {})
                    break

            if cpc_entry is not None:
                cpc_title = cpc_entry.get("Title", "")
                cpc_msg = cpc_entry.get("Message", "")
                cpc_new = cpc_entry.get("message", "")

                

                response_data = {
                    "cpc": {
                        "id" : 6,
                        "title": cpc_title,
                        "msg": cpc_msg,
                        "color": color,
                        "value": cpc_metrics,
                        "target": cpc_settings,
                        "massage": cpc_new
                    }
                }

                suggestions.append(response_data)

        formatted_keys = ["cpc", "cpr"]
        for key in formatted_keys:
            # Periksa apakah key ada di dalam suggestions
            if any(entry.get(key) for entry in suggestions):
                for entry in suggestions:
                    if key in entry:
                        formatted_number = numbers.format_number(entry[key]["value"], locale=culture)
                        formatted_number2 = numbers.format_number(entry[key]["target"], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            entry[key]["value"] = f"{currency} {formatted_number}"
                            entry[key]["target"] = f"< {currency} {formatted_number2}"
                        else:
                            entry[key]["value"] = f"{formatted_number} {currency}"
                            entry[key]["target"] = f"< {formatted_number2} {currency}"

        percent_keys = ["rar", "ctr", "oclp"]
        for key in percent_keys:
            # Periksa apakah key ada di dalam suggestions
            if any(entry.get(key) for entry in suggestions):
                for entry in suggestions:
                    if key in entry:
                        entry[key]["value"] = f"{float(entry[key]['value']):.1f}%"
                        entry[key]["target"] = f"> {float(entry[key]['target']):.1f}%"

        x_keys = ["roas"]
        for key in x_keys:
            # Periksa apakah key ada di dalam suggestions
            if any(entry.get(key) for entry in suggestions):
                for entry in suggestions:
                    if key in entry:
                        entry[key]["value"] = f"{float(entry[key]['value']):.1f}x"
                        entry[key]["target"] = f"> {float(entry[key]['target']):.1f}x"


        # Gabungkan pesan-pesan saran jika keduanya kurang dari nilai yang ditentukan
        color_priority = {"Danger": 2, "Warning": 1, "Success": 0}

        # Urutkan suggestions berdasarkan urutan prioritas warna
        sorted_suggestions = sorted(
            suggestions,
            key=lambda x: color_priority[x[list(x.keys())[0]]["color"]],
            reverse=True
        )

        # Gabungkan pesan-pesan saran
        response = {}
        for entry in sorted_suggestions:
            for key, value in entry.items():
                response[key] = value

        return {"IsError": False, "Output": f"Suggestions Data by CampaignId: {campaign_id}", "Data": [response]}

    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Membaca data dari file suggestions.json
            with open('suggestions.json', 'r') as json_file:
                existing_json_data = json.load(json_file)
            # Periksa apakah campaign_id ada dalam koleksi "settings"
            existing_settings_data = settings_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if existing_settings_data is None:
                raise HTTPException(status_code=404, detail="campaign not found in the settings collections")

            # Periksa apakah id_metrics ada dalam koleksi "metrics"
            existing_metrics_data = metrics_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if existing_metrics_data is None:
                raise HTTPException(status_code=404, detail="campaign not found in the metrics collections")

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            culture = get_campaign_culture(campaign_id)
            # Ambil nilai 'rar' dari koleksi "metrics"
            rar_metrics = existing_metrics_data.get("rar", "")

            # Ambil nilai 'rar' dari koleksi "settings"
            rar_settings = existing_settings_data.get("rar", "")

            # Ambil nilai 'cpc' dari koleksi "metrics"
            cpc_metrics = existing_metrics_data.get("cpc", "")

            # Ambil nilai 'cpc' dari koleksi "settings"
            cpc_settings = existing_settings_data.get("cpc", "")

            # Ambil nilai 'ctr' dari koleksi "metrics"
            ctr_metrics = existing_metrics_data.get("ctr", "")

            # Ambil nilai 'ctr' dari koleksi "settings"
            ctr_settings = existing_settings_data.get("ctr", "")

            # Ambil nilai 'oclp' dari koleksi "metrics"
            oclp_metrics = existing_metrics_data.get("oclp", "")

            # Ambil nilai 'oclp' dari koleksi "settings"
            oclp_settings = existing_settings_data.get("oclp", "")

            # Ambil nilai 'cpr' dari koleksi "metrics"
            cpr_metrics = existing_metrics_data.get("cpr", "")

            # Ambil nilai 'cpr' dari koleksi "settings"
            cpr_settings = existing_settings_data.get("cpr", "")

            # Ambil nilai 'roas' dari koleksi "metrics"
            roas_metrics = existing_metrics_data.get("roas", "")

            # Ambil nilai 'roas' dari koleksi "settings"
            roas_settings = existing_settings_data.get("roas", "")

            suggestions = []

        if float(rar_metrics) > float(rar_settings):
            suggestion_type = "Success"
            color = "Success"

        elif float(rar_metrics) == float(rar_settings):
            suggestion_type = "Warning"
            color = "Warning"

        else:
            suggestion_type = "Danger"
            color = "Warning"

            rar_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    rar_entry = entry[culture].get("RAR", {}).get(suggestion_type, {})
                    break

            if rar_entry is not None:
                rar_title = rar_entry.get("Title", "")
                rar_msg = rar_entry.get("Message", "")
                rar_new = rar_entry.get("message", "")

                response_data = {
                    "rar": {
                        "id" : 1,
                        "title": rar_title,
                        "msg": rar_msg,
                        "color": color,
                        "value": rar_metrics,
                        "target": rar_settings,
                        "message": rar_new
                    }
                }

                suggestions.append(response_data)

        if oclp_metrics and oclp_settings:
            if float(oclp_metrics) > float(oclp_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(oclp_metrics) == float(oclp_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            oclp_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    oclp_entry = entry[culture].get("OCLP", {}).get(suggestion_type, {})
                    break

            if oclp_entry is not None:
                oclp_title = oclp_entry.get("Title", "")
                oclp_msg = oclp_entry.get("Message", "")
                oclp_new = oclp_entry.get("message", "")

                response_data = {
                    "oclp": {
                        "id" : 2,
                        "title": oclp_title,
                        "msg": oclp_msg,
                        "color": color,
                        "value": oclp_metrics,
                        "target": oclp_settings,
                        "massage": oclp_new
                    }
                }

                suggestions.append(response_data)

        if ctr_metrics and ctr_settings:
            if float(ctr_metrics) > float(ctr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(ctr_metrics) == float(ctr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            ctr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    ctr_entry = entry[culture].get("CTR", {}).get(suggestion_type, {})
                    break

            if ctr_entry is not None:
                ctr_title = ctr_entry.get("Title", "")
                ctr_msg = ctr_entry.get("Message", "")
                ctr_new = ctr_entry.get("message", "")

                response_data = {
                    "ctr": {
                        "id" : 3,
                        "title": ctr_title,
                        "msg": ctr_msg,
                        "color": color,
                        "value": ctr_metrics,
                        "target": ctr_settings,
                        "message": ctr_new
                    }
                }

                suggestions.append(response_data)

        if roas_metrics and roas_settings:
            if float(roas_metrics) > float(roas_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(roas_metrics) == float(roas_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            roas_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    roas_entry = entry[culture].get("ROAS", {}).get(suggestion_type, {})
                    break

            if roas_entry is not None:
                roas_title = roas_entry.get("Title", "")
                roas_msg = roas_entry.get("Message", "")
                roas_new = roas_entry.get("message", "")

                response_data = {
                    "roas": {
                        "id" : 4,
                        "title": roas_title,
                        "msg": roas_msg,
                        "color": color,
                        "value": roas_metrics,
                        "target": roas_settings,
                        "message": roas_new
                    }
                }

                suggestions.append(response_data)

        if cpr_metrics and cpr_settings:
            if float(cpr_metrics) < float(cpr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpr_metrics) == float(cpr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpr_entry = entry[culture].get("CPR", {}).get(suggestion_type, {})
                    break

            if cpr_entry is not None:
                cpr_title = cpr_entry.get("Title", "")
                cpr_msg = cpr_entry.get("Message", "")
                cpr_new = cpr_entry.get("message", "")

                response_data = {
                    "cpr": {
                        "id" : 5,
                        "title": cpr_title,
                        "msg": cpr_msg,
                        "color": color,
                        "value": cpr_metrics,
                        "target": cpr_settings,
                        "message": cpr_new
                    }
                }

                suggestions.append(response_data)

        if cpc_metrics and cpc_settings:
            if float(cpc_metrics) < float(cpc_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpc_metrics) == float(cpc_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpc_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpc_entry = entry[culture].get("CPC", {}).get(suggestion_type, {})
                    break

            if cpc_entry is not None:
                cpc_title = cpc_entry.get("Title", "")
                cpc_msg = cpc_entry.get("Message", "")
                cpc_new = cpc_entry.get("message", "")

                response_data = {
                    "cpc": {
                        "id" : 6,
                        "title": cpc_title,
                        "msg": cpc_msg,
                        "color": color,
                        "value": cpc_metrics,
                        "target": cpc_settings,
                        "message": cpc_new
                    }
                }

                suggestions.append(response_data)

            formatted_keys = ["cpc", "cpr"]
            for key in formatted_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            formatted_number = numbers.format_number(entry[key]["value"], locale=culture)
                            formatted_number2 = numbers.format_number(entry[key]["target"], locale=culture)

                            # Menambahkan currency_position ke dalam amountspent
                            if currency_position:
                                entry[key]["value"] = f"{currency} {formatted_number}"
                                entry[key]["target"] = f"< {currency} {formatted_number2}"
                            else:
                                entry[key]["value"] = f"{formatted_number} {currency}"
                                entry[key]["target"] = f"< {formatted_number2} {currency}"

            percent_keys = ["rar", "ctr", "oclp"]
            for key in percent_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            entry[key]["value"] = f"{float(entry[key]['value']):.1f}%"
                            entry[key]["target"] = f"> {float(entry[key]['target']):.1f}%"

            x_keys = ["roas"]
            for key in x_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            entry[key]["value"] = f"{float(entry[key]['value']):.1f}x"
                            entry[key]["target"] = f"> {float(entry[key]['target']):.1f}x"


            
        # Gabungkan pesan-pesan saran jika keduanya kurang dari nilai yang ditentukan
        color_priority = {"Danger": 2, "Warning": 1, "Success": 0}

        # Urutkan suggestions berdasarkan urutan prioritas warna
        sorted_suggestions = sorted(
            suggestions,
            key=lambda x: color_priority[x[list(x.keys())[0]]["color"]],
            reverse=True
        )

        # Gabungkan pesan-pesan saran
        response = {}
        for entry in sorted_suggestions:
            for key, value in entry.items():
                response[key] = value

        return {"IsError": False, "Output": f"Suggestions Data by CampaignId: {campaign_id}", "Data": [response]}

    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Membaca data dari file suggestions.json
            with open('suggestions.json', 'r') as json_file:
                existing_json_data = json.load(json_file)
            # Periksa apakah campaign_id ada dalam koleksi "settings"
            existing_settings_data = settings_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if existing_settings_data is None:
                raise HTTPException(status_code=404, detail="campaign not found in the settings collections")

            # Periksa apakah id_metrics ada dalam koleksi "metrics"
            existing_metrics_data = metrics_collection.find_one({"campaign_id": campaign_id, "tenant_id": tenant_id})
            if existing_metrics_data is None:
                raise HTTPException(status_code=404, detail="campaign not found in the metrics collections")

            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            culture = get_campaign_culture(campaign_id)
            # Ambil nilai 'rar' dari koleksi "metrics"
            rar_metrics = existing_metrics_data.get("rar", "")

            # Ambil nilai 'rar' dari koleksi "settings"
            rar_settings = existing_settings_data.get("rar", "")

            # Ambil nilai 'cpc' dari koleksi "metrics"
            cpc_metrics = existing_metrics_data.get("cpc", "")

            # Ambil nilai 'cpc' dari koleksi "settings"
            cpc_settings = existing_settings_data.get("cpc", "")

            # Ambil nilai 'ctr' dari koleksi "metrics"
            ctr_metrics = existing_metrics_data.get("ctr", "")

            # Ambil nilai 'ctr' dari koleksi "settings"
            ctr_settings = existing_settings_data.get("ctr", "")

            # Ambil nilai 'oclp' dari koleksi "metrics"
            oclp_metrics = existing_metrics_data.get("oclp", "")

            # Ambil nilai 'oclp' dari koleksi "settings"
            oclp_settings = existing_settings_data.get("oclp", "")

            # Ambil nilai 'cpr' dari koleksi "metrics"
            cpr_metrics = existing_metrics_data.get("cpr", "")

            # Ambil nilai 'cpr' dari koleksi "settings"
            cpr_settings = existing_settings_data.get("cpr", "")

            # Ambil nilai 'roas' dari koleksi "metrics"
            roas_metrics = existing_metrics_data.get("roas", "")

            # Ambil nilai 'roas' dari koleksi "settings"
            roas_settings = existing_settings_data.get("roas", "")

            suggestions = []

        if float(rar_metrics) > float(rar_settings):
            suggestion_type = "Success"
            color = "Success"

        elif float(rar_metrics) == float(rar_settings):
            suggestion_type = "Warning"
            color = "Warning"

        else:
            suggestion_type = "Danger"
            color = "Warning"

            rar_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    rar_entry = entry[culture].get("RAR", {}).get(suggestion_type, {})
                    break

            if rar_entry is not None:
                rar_title = rar_entry.get("Title", "")
                rar_msg = rar_entry.get("Message", "")
                rar_new = rar_entry.get("message", "")

                response_data = {
                    "rar": {
                        "id" : 1,
                        "title": rar_title,
                        "msg": rar_msg,
                        "color": color,
                        "value": rar_metrics,
                        "target": rar_settings,
                        "message": rar_new
                    }
                }

                suggestions.append(response_data)

        if oclp_metrics and oclp_settings:
            if float(oclp_metrics) > float(oclp_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(oclp_metrics) == float(oclp_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            oclp_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    oclp_entry = entry[culture].get("OCLP", {}).get(suggestion_type, {})
                    break

            if oclp_entry is not None:
                oclp_title = oclp_entry.get("Title", "")
                oclp_msg = oclp_entry.get("Message", "")
                oclp_new = oclp_entry.get("message", "")

                response_data = {
                    "oclp": {
                        "id" : 2,
                        "title": oclp_title,
                        "msg": oclp_msg,
                        "color": color,
                        "value": oclp_metrics,
                        "target": oclp_settings,
                        "massage": oclp_new
                    }
                }

                suggestions.append(response_data)

        if ctr_metrics and ctr_settings:
            if float(ctr_metrics) > float(ctr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(ctr_metrics) == float(ctr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            ctr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    ctr_entry = entry[culture].get("CTR", {}).get(suggestion_type, {})
                    break

            if ctr_entry is not None:
                ctr_title = ctr_entry.get("Title", "")
                ctr_msg = ctr_entry.get("Message", "")
                ctr_new = ctr_entry.get("message", "")

                response_data = {
                    "ctr": {
                        "id" : 3,
                        "title": ctr_title,
                        "msg": ctr_msg,
                        "color": color,
                        "value": ctr_metrics,
                        "target": ctr_settings,
                        "message": ctr_new
                    }
                }

                suggestions.append(response_data)

        if roas_metrics and roas_settings:
            if float(roas_metrics) > float(roas_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(roas_metrics) == float(roas_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            roas_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    roas_entry = entry[culture].get("ROAS", {}).get(suggestion_type, {})
                    break

            if roas_entry is not None:
                roas_title = roas_entry.get("Title", "")
                roas_msg = roas_entry.get("Message", "")
                roas_new = roas_entry.get("message", "")

                response_data = {
                    "roas": {
                        "id" : 4,
                        "title": roas_title,
                        "msg": roas_msg,
                        "color": color,
                        "value": roas_metrics,
                        "target": roas_settings,
                        "message": roas_new
                    }
                }

                suggestions.append(response_data)

        if cpr_metrics and cpr_settings:
            if float(cpr_metrics) < float(cpr_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpr_metrics) == float(cpr_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpr_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpr_entry = entry[culture].get("CPR", {}).get(suggestion_type, {})
                    break

            if cpr_entry is not None:
                cpr_title = cpr_entry.get("Title", "")
                cpr_msg = cpr_entry.get("Message", "")
                cpr_new = cpr_entry.get("message", "")

                response_data = {
                    "cpr": {
                        "id" : 5,
                        "title": cpr_title,
                        "msg": cpr_msg,
                        "color": color,
                        "value": cpr_metrics,
                        "target": cpr_settings,
                        "message": cpr_new
                    }
                }

                suggestions.append(response_data)

        if cpc_metrics and cpc_settings:
            if float(cpc_metrics) < float(cpc_settings):
                suggestion_type = "Success"
                color = "Success"
            elif float(cpc_metrics) == float(cpc_settings):
                suggestion_type = "Warning"
                color = "Warning"
            else:
                suggestion_type = "Danger"
                color = "Warning"

            cpc_entry = None
            for entry in existing_json_data:
                if culture in entry:
                    cpc_entry = entry[culture].get("CPC", {}).get(suggestion_type, {})
                    break

            if cpc_entry is not None:
                cpc_title = cpc_entry.get("Title", "")
                cpc_msg = cpc_entry.get("Message", "")
                cpc_new = cpc_entry.get("message", "")

                response_data = {
                    "cpc": {
                        "id" : 6,
                        "title": cpc_title,
                        "msg": cpc_msg,
                        "color": color,
                        "value": cpc_metrics,
                        "target": cpc_settings,
                        "message": cpc_new
                    }
                }

                suggestions.append(response_data)

            formatted_keys = ["cpc", "cpr"]
            for key in formatted_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            formatted_number = numbers.format_number(entry[key]["value"], locale=culture)
                            formatted_number2 = numbers.format_number(entry[key]["target"], locale=culture)

                            # Menambahkan currency_position ke dalam amountspent
                            if currency_position:
                                entry[key]["value"] = f"{currency} {formatted_number}"
                                entry[key]["target"] = f"< {currency} {formatted_number2}"
                            else:
                                entry[key]["value"] = f"{formatted_number} {currency}"
                                entry[key]["target"] = f"< {formatted_number2} {currency}"

            percent_keys = ["rar", "ctr", "oclp"]
            for key in percent_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            entry[key]["value"] = f"{float(entry[key]['value']):.1f}%"
                            entry[key]["target"] = f"> {float(entry[key]['target']):.1f}%"

            x_keys = ["roas"]
            for key in x_keys:
                # Periksa apakah key ada di dalam suggestions
                if any(entry.get(key) for entry in suggestions):
                    for entry in suggestions:
                        if key in entry:
                            entry[key]["value"] = f"{float(entry[key]['value']):.1f}x"
                            entry[key]["target"] = f"> {float(entry[key]['target']):.1f}x"


            # Gabungkan pesan-pesan saran jika keduanya kurang dari nilai yang ditentukan
        color_priority = {"Danger": 2, "Warning": 1, "Success": 0}

        # Urutkan suggestions berdasarkan urut
        # an prioritas warna
        sorted_suggestions = sorted(
            suggestions,
            key=lambda x: color_priority[x[list(x.keys())[0]]["color"]],
            reverse=True
        )

        # Gabungkan pesan-pesan saran
        response = {}
        for entry in sorted_suggestions:
            for key, value in entry.items():
                response[key] = value

            return {"IsError": False, "Output": f"Suggestions Data by CampaignId: {campaign_id}", "Data": [response]}

        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/last-week", tags=["Performance"])
def last_week(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)

        # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
        clients = list(history_collection.find(
            {"campaign_id": campaign_id, "tenant_id": tenantId, "timestamp_update": {"$gte": seven_days_ago}},
            sort=[("timestamp_update", DESCENDING)],
            limit=7
        ))
        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_update" in client:
                client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]

        return {"IsError": False, "Output": f"Last Week History Metrics by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Week History Metrics by CampaignId: {campaign_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "client_id": user_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Week History Metrics by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/last-month", tags=["Performance"])
def last_month(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        seven_days_ago = datetime.utcnow() - timedelta(days=31)

        # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
        clients = list(history_collection.find(
            {"campaign_id": campaign_id, "tenant_id": tenantId, "timestamp_update": {"$gte": seven_days_ago}},
            sort=[("timestamp_update", DESCENDING)]
        ))
        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_update" in client:
                client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]

        return {"IsError": False, "Output": f"Last Month History Metrics by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Month History Metrics by CampaignId: {campaign_id}", "Data": clients}
    
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "client_id": user_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Month History Metrics by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/last-year", tags=["Performance"])
def last_year(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        seven_days_ago = datetime.utcnow() - timedelta(days=365)

        # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
        clients = list(history_collection.find(
            {"campaign_id": campaign_id, "tenant_id": tenantId, "timestamp_update": {"$gte": seven_days_ago}},
            sort=[("timestamp_update", DESCENDING)]
        ))
        # Mengambil nilai currency dan currency_position dari koleksi campaigns
        campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
        currency = campaign_data.get("currency", "")
        currency_position = campaign_data.get("currency_position", True)

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

            # Ubah format angka berdasarkan culture dan tambahkan currency
            formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
            for key in formatted_keys:
                if key in client:
                    formatted_number = numbers.format_number(client[key], locale=culture)

                    # Menambahkan currency_position ke dalam amountspent
                    if currency_position:
                        client[key] = f"{currency} {formatted_number}"
                    else:
                        client[key] = f"{formatted_number} {currency}"

            formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
            for key in formatted_keys:
                if key in client:
                    client[key] = numbers.format_number(client[key], locale=culture)

            percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
            for key in percent_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}%"

            x_keys = ["roas", "realroas"]
            for key in x_keys:
                if key in client:
                    client[key] = f"{client[key]:.1f}x"

            if "frequency" in client:
                client["frequency"] = str(client["frequency"])

            if "timestamp_update" in client:
                client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]

        return {"IsError": False, "Output": f"Last Year History Metrics by CampaignId: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Year History Metrics by CampaignId: {campaign_id}", "Data": clients}
    
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)

            # Mengambil 7 data terakhir dari 7 hari terakhir berdasarkan timestamp_update
            clients = list(history_collection.find(
                {"campaign_id": campaign_id, "client_id": user_id, "tenant_id": tenant_id, "timestamp_update": {"$gte": seven_days_ago}},
                sort=[("timestamp_update", DESCENDING)]
            ))
            # Mengambil nilai currency dan currency_position dari koleksi campaigns
            campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
            currency = campaign_data.get("currency", "")
            currency_position = campaign_data.get("currency_position", True)

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        client["timestamp_update"] = format_timestamp(client["timestamp_update"], culture, timezone_name)
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

                # Ubah format angka berdasarkan culture dan tambahkan currency
                formatted_keys = ["amountspent", "cpc", "cpr", "purchase", "cpm"]
                for key in formatted_keys:
                    if key in client:
                        formatted_number = numbers.format_number(client[key], locale=culture)

                        # Menambahkan currency_position ke dalam amountspent
                        if currency_position:
                            client[key] = f"{currency} {formatted_number}"
                        else:
                            client[key] = f"{formatted_number} {currency}"

                formatted_keys = ["reach", "impressions", "clicks", "lpview", "ctview", "results", "leads"]
                for key in formatted_keys:
                    if key in client:
                        client[key] = numbers.format_number(client[key], locale=culture)

                percent_keys = ["rar", "ctr", "oclp", "atc", "delivery"]
                for key in percent_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}%"

                x_keys = ["roas", "realroas"]
                for key in x_keys:
                    if key in client:
                        client[key] = f"{client[key]:.1f}x"

                if "frequency" in client:
                    client["frequency"] = str(client["frequency"])

                if "timestamp_update" in client:
                    client["timestamp_update"] = client["timestamp_update"].rsplit('.', 1)[0]
                    
            return {"IsError": False, "Output": f"Last Year History Metrics by CampaignId: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


#campaigns

@app.post("/campaign-create", tags=["Campaigns"])
def create_campaign(
    name: str = Form(...),
    account_id: str = Form(...),
    objective: int = Form(...),
    start_date: str = Form(..., description="yyyy-mm-dd"),
    end_date: str = Form(..., description="yyyy-mm-dd"),
    status: int = Form(..., description="1/2/3"),
    notes: str = Form(...),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin" )):

    if "sadmin" in roles:
        account_data = accounts_collection.find_one({"_id": ObjectId(account_id)})
        if not account_data:
            raise HTTPException(status_code=404, detail="Account not found")
        
        client_id = account_data["client_id"]

        # Check if the provided client_id exists in the clients_collection
        client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
        if not client_data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        tenant_data = tenant_collection.find_one({"_id": ObjectId(tenantId)})
        if not tenant_data:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        input_timezone = tenant_data["timezone_name"]
        
        nama_tenant = get_nama_tenant(tenant_collection, tenantId)

        current_time_utc = datetime.now(utc)

        try:
            # Parse input manual start_date dan end_date dari string ke datetime
            user_input_start_date = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(milliseconds=1)
            user_input_end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(milliseconds=1)

            # Konversi input start_date dan end_date ke UTC
            user_input_start_date_utc = user_input_start_date.replace(tzinfo=utc)
            user_input_end_date_utc = user_input_end_date.replace(tzinfo=utc)

        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")

        campaigns = {
            "name": name,
            "client_id": client_id,
            "client_name": client_data["name"],
            "account_id": account_id,
            "account_name": account_data["username"],
            "platform": account_data["platform"],
            "objective": objective,
            "status": status,
            "notes": notes,
            "language": tenant_data["language"],
            "culture": tenant_data["culture"],
            "currency": tenant_data["currency"],
            "currency_position": tenant_data["currency_position"],
            "company_name": nama_tenant,
            "tenant_id": tenantId,
            "start_date": user_input_start_date_utc,
            "end_date": user_input_end_date_utc,
            "timezone_name": input_timezone
        }

        insert_result = campaigns_collection.insert_one(campaigns)
        projection = {"_id": False}
        result = campaigns_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        
        return {"IsError": False, "Output": "Create Campaign Successfully", "Data": result }
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan: 
            account_data = accounts_collection.find_one({"_id": ObjectId(account_id)})
            if not account_data:
                raise HTTPException(status_code=404, detail="Account not found")
            
            client_id = account_data["client_id"]

            # Check if the provided client_id exists in the clients_collection
            client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
            if not client_data:
                raise HTTPException(status_code=404, detail="Client not found")
            
            tenant_data = tenant_collection.find_one({"_id": ObjectId(tenant_id)})
            if not tenant_data:
                raise HTTPException(status_code=404, detail="Tenant not found")
            
            input_timezone = tenant_data["timezone_name"]
            
            nama_tenant = get_nama_tenant(tenant_collection, tenant_id)

            current_time_utc = datetime.now(utc)

            try:
                # Parse input manual start_date dan end_date dari string ke datetime
                user_input_start_date = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(milliseconds=1)
                user_input_end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(milliseconds=1)

                # Konversi input start_date dan end_date ke UTC
                user_input_start_date_utc = user_input_start_date.replace(tzinfo=utc)
                user_input_end_date_utc = user_input_end_date.replace(tzinfo=utc)

            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")

            campaigns = {
                "name": name,
                "client_id": client_id,
                "client_name": client_data["name"],
                "account_id": account_id,
                "account_name": account_data["username"],
                "platform": account_data["platform"],
                "objective": objective,
                "status": status,
                "notes": notes,
                "language": tenant_data["language"],
                "culture": tenant_data["culture"],
                "currency": tenant_data["currency"],
                "currency_position": tenant_data["currency_position"],
                "company_name": nama_tenant,
                "tenant_id": tenant_id,
                "start_date": user_input_start_date_utc,
                "end_date": user_input_end_date_utc,
                "timezone_name": input_timezone
            }

            insert_result = campaigns_collection.insert_one(campaigns)
            projection = {"_id": False}
            result = campaigns_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
            
            return {"IsError": False, "Output": "Create Campaign Successfully", "Data": result }
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})
    
@app.put("/campaign-edit", tags=["Campaigns"])
def edit_campaign(
    campaign_id: str,
    name: str = Form(None),
    account_id: str = Form(None),
    platform: int = Form(None),
    objective: int = Form(None),
    start_date: str = Form(..., description="yyyy-mm-dd"),
    end_date: str = Form(..., description="yyyy-mm-dd"),
    status: int = Form(None, description="1/2/3"),
    notes: str = Form(None),
    language: str = Form(None),
    culture: str = Form(None, description="example = en_US, id_ID"),
    input_timezone: str = Form(None),
    currency: str = Form(None),
    currency_position: bool = Form(None),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):

    if "sadmin" in roles:
        # Cari entri profil berdasarkan ID
        existing_profil = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})

        if not existing_profil:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
        
        current_time_utc = datetime.now(utc)

        # Ambil zona waktu dari data sebelumnya jika input_timezone kosong
        if not input_timezone:
            input_timezone = existing_profil.get("timezone_name", "UTC")

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")


        # Update data Periode
        update_data = {}
        if name is not None and name != "":
            update_data["name"] = name
        if account_id is not None:
            account_data = accounts_collection.find_one({"_id": ObjectId(account_id)})
            if not account_data:
                raise HTTPException(status_code=404, detail="Account not found")
            update_data["account_id"] = account_id
            update_data["account_name"] = account_data["username"]
            update_data["client_id"] = account_data["client_id"]
            update_data["client_name"] = account_data["client_name"]
        if platform is not None:
            update_data["platform"] = platform
        if objective is not None:
            update_data["objective"] = objective
        if start_date is not None:
            try:
                # Parse input manual start_date dan end_date dari string ke datetime
                user_input_start_date = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(milliseconds=1)
                # Konversi input start_date dan end_date ke UTC
                user_input_start_date_utc = user_input_start_date.replace(tzinfo=utc)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
            update_data["start_date"] = user_input_start_date_utc
        if end_date is not None:
            try:
                # Parse input manual end_date dan end_date dari string ke datetime
                user_input_end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(milliseconds=1)
                # Konversi input end_date dan end_date ke UTC
                user_input_end_date_utc = user_input_end_date.replace(tzinfo=utc)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
            update_data["end_date"] = user_input_end_date_utc
        if status is not None:
            update_data["status"] = status
        if notes is not None:
            update_data["notes"] = notes
        if language is not None:
            update_data["language"] = language
        if culture is not None:
            update_data["culture"] = culture.replace("-", "_")
        if currency is not None:
            currency_symbol = currency.replace(" ", "").split("-")[0].strip()
            update_data["currency"] = currency_symbol
        if currency_position is not None:
            update_data["currency_position"] = currency_position

        update_data["timestamp_update"] = localized_time  # Update timestamp
          # Update zona waktu
        update_data["timezone_name"] = input_timezone

        if update_data:
            campaigns_collection.update_one({"_id": ObjectId(campaign_id)}, {"$set": update_data})
            projection = {"_id": False}
            result = campaigns_collection.find_one({"_id": ObjectId(campaign_id)}, projection=projection)

        return {"IsError": False, "Output": "Campaign Successfully edited", "Data": result}
    
    if "admin" in roles or "staff" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
        # Cari entri profil berdasarkan ID
            existing_profil = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})

            if not existing_profil:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
            
            current_time_utc = datetime.now(utc)

            # Ambil zona waktu dari data sebelumnya jika input_timezone kosong
            if not input_timezone:
                input_timezone = existing_profil.get("timezone_name", "UTC")

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")


            # Update data Periode
            update_data = {}
            if name is not None and name != "":
                update_data["name"] = name
            if account_id is not None:
                account_data = accounts_collection.find_one({"_id": ObjectId(account_id)})
                if not account_data:
                    raise HTTPException(status_code=404, detail="Account not found")
                update_data["account_id"] = account_id
                update_data["account_name"] = account_data["username"]
                update_data["client_id"] = account_data["client_id"]
                update_data["client_name"] = account_data["client_name"]
            if platform is not None:
                update_data["platform"] = platform
            if objective is not None:
                update_data["objective"] = objective
            if start_date is not None:
                try:
                    # Parse input manual start_date dan end_date dari string ke datetime
                    user_input_start_date = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(milliseconds=1)
                    # Konversi input start_date dan end_date ke UTC
                    user_input_start_date_utc = user_input_start_date.replace(tzinfo=utc)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
                update_data["start_date"] = user_input_start_date_utc
            if end_date is not None:
                try:
                    # Parse input manual end_date dan end_date dari string ke datetime
                    user_input_end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(milliseconds=1)
                    # Konversi input end_date dan end_date ke UTC
                    user_input_end_date_utc = user_input_end_date.replace(tzinfo=utc)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
                update_data["end_date"] = user_input_end_date_utc
            if status is not None:
                update_data["status"] = status
            if notes is not None:
                update_data["notes"] = notes
            if language is not None:
                update_data["language"] = language
            if culture is not None:
                update_data["culture"] = culture.replace("-", "_")
            if currency is not None:
                currency_symbol = currency.replace(" ", "").split("-")[0].strip()
                update_data["currency"] = currency_symbol
            if currency_position is not None:
                update_data["currency_position"] = currency_position

            update_data["timestamp_update"] = localized_time  # Update timestamp
            # Update zona waktu
            update_data["timezone_name"] = input_timezone

            if update_data:
                campaigns_collection.update_one({"_id": ObjectId(campaign_id)}, {"$set": update_data})
                projection = {"_id": False}
                result = campaigns_collection.find_one({"_id": ObjectId(campaign_id)}, projection=projection)

            return {"IsError": False, "Output": "Campaign Successfully edited", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.delete("/campaign-delete", tags=["Campaigns"], dependencies=[Depends(get_current_user)])
def delete_campaign(campaign_id: str, 
    roles: str = Depends(get_current_user),    
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):
    if "sadmin" in roles:
        
        obj_id = ObjectId(campaign_id)

        clients = campaigns_collection.find_one({"_id": obj_id})
        if clients is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
        
        campaigns_collection.delete_one({"_id": obj_id})
        # Hapus tenant berdasarkan tenant_id yang sama
        for collection in [metrics_collection, settings_collection, history_collection]:
            collection.delete_many({"campaign_id": str(obj_id)})

        return {"IsError": False, "Output": "Campaign Successfully deleted"}
    
    if "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(campaign_id)
            # Now you can use the decoded "id" parameter in your database query
            clients = campaigns_collection.find_one({"_id": obj_id, "tenant_id": perusahaan})
            if clients is None:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Campaign not found", "Output": ""})
            
            campaigns_collection.delete_one({"_id": obj_id, "tenant_id": perusahaan})
            # Hapus tenant berdasarkan tenant_id yang sama
            for collection in [metrics_collection, settings_collection, history_collection]:
                collection.delete_many({"campaign_id": str(obj_id)})

            return {"IsError": False, "Output": "Data Deleted Successfully"}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permission for this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/campaign-by-id", tags=["Campaigns"])
def get_campaign(
    campaign_id: str,
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        clients = list(campaigns_collection.find({"_id": ObjectId(campaign_id),"tenant_id": tenantId}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(campaign_id)
            timezone_name = get_campaign_timezone(campaign_id)
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["start_date"], timezone_name
                )
                client["start_date"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "end_date" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["end_date"], timezone_name
                    )
                    client["end_date"] = format_datetime(
                        localized_time, locale=culture
                    )

            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Campaign Data by Id: {campaign_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles or "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            clients = list(campaigns_collection.find({"_id": ObjectId(campaign_id),"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(campaign_id)
                timezone_name = get_campaign_timezone(campaign_id)
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["start_date"], timezone_name
                    )
                    client["start_date"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "end_date" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["end_date"], timezone_name
                        )
                        client["end_date"] = format_datetime(
                            localized_time, locale=culture
                        )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Campaign Data by Id: {campaign_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/campaign-by-tenant", tags=["Campaigns"])
def get_all_campaigns(    
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        # Check if tenantId is provided
        if tenantId:
            # Implementasi endpoint dengan dependensi tenantId
            clients = list(campaigns_collection.find({"tenant_id": tenantId}))
        else:
            # Implementasi endpoint tanpa dependensi tenantId (retrieve all data)
            clients = list(campaigns_collection.find({}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_campaign_culture(str(client["_id"]))
            timezone_name = get_campaign_timezone(str(client["_id"]))
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["start_date"], timezone_name
                )
                client["start_date"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "end_date" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["end_date"], timezone_name
                    )
                    client["end_date"] = format_datetime(
                        localized_time, locale=culture
                    )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Campaign Data by TenantId: {tenantId}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(campaigns_collection.find({"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(str(client["_id"]))
                timezone_name = get_campaign_timezone(str(client["_id"]))
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["start_date"], timezone_name
                    )
                    client["start_date"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "end_date" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["end_date"], timezone_name
                        )
                        client["end_date"] = format_datetime(
                            localized_time, locale=culture
                        )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Campaign Data by TenantId: {tenant_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(campaigns_collection.find({"client_id": user_id, "tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_campaign_culture(str(client["_id"]))
                timezone_name = get_campaign_timezone(str(client["_id"]))
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["start_date"], timezone_name
                    )
                    client["start_date"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "end_date" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["end_date"], timezone_name
                        )
                        client["end_date"] = format_datetime(
                            localized_time, locale=culture
                        )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Campaign Data by TenantId: {tenant_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


#accountt

@app.post("/account-create", tags=["Accounts"], dependencies=[Depends(get_current_user)])
def create_account(
    username: str = Form(...),
    client_id: str = Form(...),
    platform: int = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    notes: str = Form(...),
    status: int = Form(...),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None,description="Hanya Untuk SuperAdmin" )):

    if "sadmin" in roles:
        # Check if the provided client_id exists in the clients_collection
        client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
        if not client_data:
            raise HTTPException(status_code=404, detail="Client not found")

        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
        
        # Validasi konfirmasi password
        if password != confirm_password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
        # Periksa apakah clients sudah ada dalam database

        nama_tenant = get_nama_tenant(tenant_collection, tenantId)
        # Create a new account document
        new_account = {
            "username": username,
            "client_id": client_id,
            "client_name": client_data["name"],
            "platform": platform,
            "email": email,
            "password": password,
            "notes": notes,
            "status": status,
            "company_name": nama_tenant,
            "tenant_id": tenantId,
        }

        # Insert the new account into the accounts_collection
        insert_result = accounts_collection.insert_one(new_account)
        projection = {"_id": False}
        result = accounts_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        
        
        return {"IsError": False, "Output": "Create Account Successfully", "Data": result }

    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:    
            # Check if the provided client_id exists in the clients_collection
            client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
            if not client_data:
                raise HTTPException(status_code=404, detail="Client not found")

            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
            
            # Validasi konfirmasi password
            if password != confirm_password:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
            # Periksa apakah clients sudah ada dalam database

            nama_tenant = get_nama_tenant(tenant_collection, tenant_id)
            # Create a new account document
            new_account = {
                "username": username,
                "client_id": client_id,
                "client_name": client_data["name"],
                "platform": platform,
                "email": email,
                "password": password,
                "notes": notes,
                "status": status,
                "company_name": nama_tenant,
                "tenant_id": tenant_id,
            }

            # Insert the new account into the accounts_collection
            insert_result = accounts_collection.insert_one(new_account)
            projection = {"_id": False}
            result = accounts_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
            
            
            return {"IsError": False, "Output": "Create Account Successfully", "Data": result }
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.put("/account-edit", tags=["Accounts"], dependencies=[Depends(get_current_user)])
def edit_account(
    account_id: str,
    username: str = Form(None),
    client_id: str = Form(None),
    platform: int = Form(None),
    email: str = Form(None),
    password: str = Form(None),
    confirm_password: str = Form(None),
    notes: str = Form(None),
    status: int = Form(None),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):

    if "sadmin" in roles:
        # Periksa apakah accounts ada dalam database
        existing_account = accounts_collection.find_one({"_id": ObjectId(account_id)})
        if not existing_account:
            raise HTTPException(status_code=404, detail="accounts tidak ditemukan")

        # Update data accounts jika nilai yang baru diberikan
        update_data = {}
        if username is not None:
            update_data["username"] = username
            # Update nama di koleksi lainnya
            for collection in [campaigns_collection]:
                collection.update_many({"account_id": str(account_id)}, {"$set": {"account_name": username}})
        if client_id is not None:
            client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
            if not client_data:
                raise HTTPException(status_code=404, detail="Client not found")
            update_data["client_id"] = client_id
            update_data["client_name"] = client_data["name"]
        if platform is not None:
            update_data["platform"] = platform
        if email is not None:
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
            update_data["email"] = email
        if password is not None:
            if password != confirm_password:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
            update_data["password"] = password
        if notes is not None:
            update_data["notes"] = notes
        if status is not None:
            update_data["status"] = status

        # Lakukan pembaruan data jika ada data yang harus diperbarui
        if update_data:
            accounts_collection.update_one({"_id": ObjectId(account_id)}, {"$set": update_data})
            projection = {"_id": False}
            result = accounts_collection.find_one({"_id": ObjectId(account_id)}, projection=projection)

        return {"IsError": False, "Output": "Data Updated Successfully", "Data": result}
    if "admin" in roles or "staff" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Periksa apakah accounts ada dalam database
            existing_account = accounts_collection.find_one({"_id": ObjectId(account_id)})
            if not existing_account:
                raise HTTPException(status_code=404, detail="accounts tidak ditemukan")

            # Update data accounts jika nilai yang baru diberikan
            update_data = {}
            if username is not None:
                update_data["username"] = username
                # Update nama di koleksi lainnya
                for collection in [campaigns_collection]:
                    collection.update_many({"account_id": str(account_id)}, {"$set": {"account_name": username}})
            if client_id is not None:
                client_data = clients_collection.find_one({"_id": ObjectId(client_id)})
                if not client_data:
                    raise HTTPException(status_code=404, detail="Client not found")
                update_data["client_id"] = client_id
                update_data["client_name"] = client_data["name"]
            if platform is not None:
                update_data["platform"] = platform
            if email is not None:
                email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
                if not re.match(email_regex, email):
                    raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
                update_data["email"] = email
            if password is not None:
                if password != confirm_password:
                    raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
                update_data["password"] = password
            if notes is not None:
                update_data["notes"] = notes
            if status is not None:
                update_data["status"] = status

            # Lakukan pembaruan data jika ada data yang harus diperbarui
            if update_data:
                accounts_collection.update_one({"_id": ObjectId(account_id)}, {"$set": update_data})
                projection = {"_id": False}
                result = accounts_collection.find_one({"_id": ObjectId(account_id)}, projection=projection)

            return {"IsError": False, "Output": "Data Updated Successfully", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.delete("/account-delete", tags=["Accounts"], dependencies=[Depends(get_current_user)])
def delete_account(account_id: str, 
    roles: str = Depends(get_current_user),    
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):
    if "sadmin" in roles:
        
        obj_id = ObjectId(account_id)

        # Now you can use the decoded "id" parameter in your database query
        clients = accounts_collection.find_one({"_id": obj_id})
        if clients is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Account tidak ditemukan", "Output": ""})
        
        accounts_collection.delete_one({"_id": obj_id})
        # Hapus tenant berdasarkan tenant_id yang sama
        for collection in [campaigns_collection, metrics_collection, settings_collection, history_collection]:
            collection.delete_many({"account_id": str(obj_id)})

        return {"IsError": False, "Output": "Data Deleted Successfully"}
    if "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(account_id)
            # Now you can use the decoded "id" parameter in your database query
            clients = accounts_collection.find_one({"_id": obj_id, "tenant_id": perusahaan})
            if clients is None:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Account tidak ditemukan", "Output": ""})
            
            accounts_collection.delete_one({"_id": obj_id, "tenant_id": perusahaan})
            # Hapus tenant berdasarkan tenant_id yang sama
            for collection in [campaigns_collection, metrics_collection, settings_collection, history_collection]:
                collection.delete_many({"account_id": str(obj_id)})
                
            return {"IsError": False, "Output": "Data Deleted Successfully"}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permission for this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/account-by-id", tags=["Accounts"])
def get_account(
    account_id: str,
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        obj_id = ObjectId(account_id)
        # Implementasi endpoint tanpa dependensi
        clients = list(accounts_collection.find({"_id": obj_id,"tenant_id": tenantId}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Account Data by Id: {account_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles or "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(account_id)
            # Implementasi endpoint tanpa dependensi
            clients = list(accounts_collection.find({"_id": obj_id,"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Account Data by Id: {account_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/account-by-tenant", tags=["Accounts"])
def get_all_accounts(    
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        # Check if tenantId is provided
        if tenantId:
            # Implementasi endpoint dengan dependensi tenantId
            clients = list(accounts_collection.find({"tenant_id": tenantId}, {"password": 0}))
        else:
            # Implementasi endpoint tanpa dependensi tenantId (retrieve all data)
            clients = list(accounts_collection.find({}, {"password": 0}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Account Data by TenantId: {tenantId}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(accounts_collection.find({"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Account Data by TenantId: {tenant_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(accounts_collection.find({"client_id": user_id, "tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Account Data by TenantId: {tenant_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

#clients

@app.post("/client-create", tags=["Clients"], dependencies=[Depends(get_current_user)])
def create_client(name: str = Form(...),
    address: str = Form(...),
    contact: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    notes: str = Form(...),
    status: int = Form(..., description="1 or 2"),
    roles: str = Depends(get_current_user), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None,description="Hanya Untuk SuperAdmin" )):

    contactr = contact.replace(" ", "").replace("-", "")
    if "sadmin" in roles:
        # Validasi alamat email menggunakan regular expression
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
        
        # Validasi konfirmasi password
        if password != confirm_password:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
        # Periksa apakah clients sudah ada dalam database
        existing_clients = clients_collection.find_one({"email": email})
        if existing_clients:
            raise HTTPException(status_code=400, detail="clients sudah ada dalam database")

        nama_tenant = get_nama_tenant(tenant_collection, tenantId)

        clients_data = {
        "name": name,
        "address": address,
        "contact": contactr,
        "email": email.lower(),
        "password": password,
        "notes": notes,
        "status": status,
        "company_name": nama_tenant,
        "tenant_id": tenantId,
        "roles": "client",
        "image": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCADIAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD6YoooqzEKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiihVYttVWZv7q0AFFadro8sg3Tnyh/d+81aEWk2adUZ/wDeNLmK5TnKK6j+zrL/AJ9kqGXSLN/uqyH/AGTRzBynO0Vp3WkTxqWgbzR/d6NWYysG2su1v7tMQUUUUCCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAfbwvNKIkXcWro9PsIrRN3DSfxPUejWf2a33uP3j9fatA1BokLRRRQUFFFFABVLULCK6T+7L/C9XaKAOPuI3hlaKVdpFMrotZtPtEG9B+8Tn6iudqjKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABVrS4fPvUjb7q/M1Va1vDifvpn9FVaQ4m7RRRUmoUUUUAFFFFABRRRQAVyuqQ+Reuq/db5lrqqwvEifv4X9VZaqJMjJooopmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVr+GjzMP8AdrIrQ0KTy73a3R1xSHE6OiiipNQooooAKKKKACiiigBO1YviQ/NCv+y1bXaud16TzL/b/cXFESZbGfRRRVmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAU6N2R1dfvK25abRQM6y0mWe3SVf4v0qY1zOlXptZdrbmib73t/tV0kTrIgdGDKehFQWmPooooKCiiigAoopkjqiF3baq9TQBHeXAt7d5W/h6e9cqzM7tI33mbc1WtVvWupdq8RL0qnVRMpSCiiimIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACrNjez2p+X5k/iQ1WooGdLa6jbT/KG2P8A3Xq91rjKljuJ4/uSyL/utS5RxkddxScVyv2+8/5+H/76qKSaeX/WSyN/vNRyhznRXWpWsGV373/upWHfXs903zNtT+FBVaijlFKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUU+GOWZ9kSM59q1rTR/4rh/8AgC0hmN95ttWYbC8k+7Ayj1b5a6O3toIFxFEq/hU9HMXynPx6NO335UX/AMeqZdF/vXH5JWzxRRdhaJkf2JH/AM/D/lTW0Nf4bj80rZ4o4qeYOVGBJo06/clRv/HaqzWF5H96BmHqvzV1VFVzBynGfdba1FdZcWsE4xLErH1xWXdaN/Fbv/wB/wD4qjmJ5THop80bwvsljZT/ALVMpkhRRRQAUUUUAFFFFABRRRQAUUUUAFXtN097n55Pli/vf3qdo9h9pbzZf9UP/Hq6FQqrgUuYqMRlvBFbx7IlCipaKKk0CiiigAooooAKKKKACiiigAooooAiuIIriPZKu4Vz+o6e9r+8T54vX+7XS01grDB6UEyjzHHUVoavYfZm82L/AFR/8drPqyAooooEFFFFABRRRQAVNZwNc3CRL/wI/wB1ahrc8PQBYnnI5Y4X6UmOJpxRrGgRBtVVwKkooqTUKKKKACiiigAooooAKKKKACiiigAooooAKKKKAI5Y1ljMbruVuDXLXkDW1w8Tfw/dP95a62sjxDDmJJ16rw3+7VRJkYdFFFMzCiiigAooooAK6jS12WEK/wCxmuXrrLL/AI84P9xf5UpFRJ6KKKk0CiiigAooooAKKKKACiiigAooooAKKKKACiiigAqpqq79PmX/AGM1bqC+/wCPOb/cagDk6KKKsyCiiigQUUUUAFdZZf8AHnB/uL/KuTrrLL/jzg/3F/lSkaRJ6KKKkoKKKKACiiigAooooAKKKKACiiigAooooAKKKKACoL3/AI85/wDcb+VT1Be/8ec/+438qAOToooqzIKKKKBBRRRQAV1ll/x5wf7i/wAqKKUjSJPRRRUlBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVBe/8AHnP/ALjfyoooA5OiiirMgooooEf/2Q=="
        }
        insert_result = clients_collection.insert_one(clients_data)
        projection = {"_id": False}
        result = clients_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        
        return {"IsError": False, "Output": "Create Client Successfully", "Data": result }

    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Validasi alamat email menggunakan regular expression
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Invalid email address", "Output": ""})
            
            # Validasi konfirmasi password
            if password != confirm_password:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Password confirmation does not match the password", "Output": ""})
            # Periksa apakah clients sudah ada dalam database
            existing_clients = clients_collection.find_one({"email": email})
            if existing_clients:
                raise HTTPException(status_code=400, detail="clients sudah ada dalam database")

            nama_tenant = get_nama_tenant(tenant_collection, tenant_id)

            clients_data = {
            "name": name,
            "address": address,
            "contact": contactr,
            "email": email.lower(),
            "password": password,
            "notes": notes,
            "status": status,
            "company_name": nama_tenant,
            "tenant_id": tenant_id,
            "roles": "client",
            "image": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCADIAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD6YoooqzEKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiihVYttVWZv7q0AFFadro8sg3Tnyh/d+81aEWk2adUZ/wDeNLmK5TnKK6j+zrL/AJ9kqGXSLN/uqyH/AGTRzBynO0Vp3WkTxqWgbzR/d6NWYysG2su1v7tMQUUUUCCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAfbwvNKIkXcWro9PsIrRN3DSfxPUejWf2a33uP3j9fatA1BokLRRRQUFFFFABVLULCK6T+7L/C9XaKAOPuI3hlaKVdpFMrotZtPtEG9B+8Tn6iudqjKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABVrS4fPvUjb7q/M1Va1vDifvpn9FVaQ4m7RRRUmoUUUUAFFFFABRRRQAVyuqQ+Reuq/db5lrqqwvEifv4X9VZaqJMjJooopmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVr+GjzMP8AdrIrQ0KTy73a3R1xSHE6OiiipNQooooAKKKKACiiigBO1YviQ/NCv+y1bXaud16TzL/b/cXFESZbGfRRRVmYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAU6N2R1dfvK25abRQM6y0mWe3SVf4v0qY1zOlXptZdrbmib73t/tV0kTrIgdGDKehFQWmPooooKCiiigAoopkjqiF3baq9TQBHeXAt7d5W/h6e9cqzM7tI33mbc1WtVvWupdq8RL0qnVRMpSCiiimIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACrNjez2p+X5k/iQ1WooGdLa6jbT/KG2P8A3Xq91rjKljuJ4/uSyL/utS5RxkddxScVyv2+8/5+H/76qKSaeX/WSyN/vNRyhznRXWpWsGV373/upWHfXs903zNtT+FBVaijlFKQUUUUxBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUU+GOWZ9kSM59q1rTR/4rh/8AgC0hmN95ttWYbC8k+7Ayj1b5a6O3toIFxFEq/hU9HMXynPx6NO335UX/AMeqZdF/vXH5JWzxRRdhaJkf2JH/AM/D/lTW0Nf4bj80rZ4o4qeYOVGBJo06/clRv/HaqzWF5H96BmHqvzV1VFVzBynGfdba1FdZcWsE4xLErH1xWXdaN/Fbv/wB/wD4qjmJ5THop80bwvsljZT/ALVMpkhRRRQAUUUUAFFFFABRRRQAUUUUAFXtN097n55Pli/vf3qdo9h9pbzZf9UP/Hq6FQqrgUuYqMRlvBFbx7IlCipaKKk0CiiigAooooAKKKKACiiigAooooAiuIIriPZKu4Vz+o6e9r+8T54vX+7XS01grDB6UEyjzHHUVoavYfZm82L/AFR/8drPqyAooooEFFFFABRRRQAVNZwNc3CRL/wI/wB1ahrc8PQBYnnI5Y4X6UmOJpxRrGgRBtVVwKkooqTUKKKKACiiigAooooAKKKKACiiigAooooAKKKKAI5Y1ljMbruVuDXLXkDW1w8Tfw/dP95a62sjxDDmJJ16rw3+7VRJkYdFFFMzCiiigAooooAK6jS12WEK/wCxmuXrrLL/AI84P9xf5UpFRJ6KKKk0CiiigAooooAKKKKACiiigAooooAKKKKACiiigAqpqq79PmX/AGM1bqC+/wCPOb/cagDk6KKKsyCiiigQUUUUAFdZZf8AHnB/uL/KuTrrLL/jzg/3F/lSkaRJ6KKKkoKKKKACiiigAooooAKKKKACiiigAooooAKKKKACoL3/AI85/wDcb+VT1Be/8ec/+438qAOToooqzIKKKKBBRRRQAV1ll/x5wf7i/wAqKKUjSJPRRRUlBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVBe/8AHnP/ALjfyoooA5OiiirMgooooEf/2Q=="
            }
            insert_result = clients_collection.insert_one(clients_data)
            projection = {"_id": False}
            result = clients_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
            
            return {"IsError": False, "Output": "Create Client Successfully", "Data": result }
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.put("/client-edit", tags=["Clients"], dependencies=[Depends(get_current_user)])
def edit_client(
    client_id: str,
    name: str = Form(None),
    address: str = Form(None),
    contact: str = Form(None),
    notes: str = Form(None),
    status: int = Form(None),
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):

    if "sadmin" in roles:
        # Periksa apakah Clients ada dalam database
        existing_clients = clients_collection.find_one({"_id": ObjectId(client_id)})
        if not existing_clients:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})

        # Update data Clients jika nilai yang baru diberikan
        update_data = {}
        if name is not None:
            update_data["name"] = name
            # Update nama di koleksi lainnya
            for collection in [accounts_collection, campaigns_collection]:
                collection.update_many({"client_id": str(client_id)}, {"$set": {"client_name": name}})
        if address is not None:
            update_data["address"] = address
        if contact is not None:
            update_data["contact"] = contact
        if notes is not None:
            update_data["notes"] = notes
        if status is not None:
            update_data["status"] = status

        # Lakukan pembaruan data jika ada data yang harus diperbarui
        if update_data:
            clients_collection.update_one({"_id": ObjectId(client_id)}, {"$set": update_data})
            projection = {"_id": False}
            result = clients_collection.find_one({"_id": ObjectId(client_id)}, projection=projection)

        return {"IsError": False, "Output": "Data Updated Successfully", "Data": result}

    if "admin" in roles or "staff" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            existing_clients = clients_collection.find_one({"_id": ObjectId(client_id)})
            if not existing_clients:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})

            # Update data Clients jika nilai yang baru diberikan
            update_data = {}
            if name is not None:
                update_data["name"] = name
                # Update nama di koleksi lainnya
                for collection in [accounts_collection, campaigns_collection]:
                    collection.update_many({"client_id": str(client_id)}, {"$set": {"client_name": name}})
            if address is not None:
                update_data["address"] = address
            if contact is not None:
                update_data["contact"] = contact
            if notes is not None:
                update_data["notes"] = notes
            if status is not None:
                update_data["status"] = status

            # Lakukan pembaruan data jika ada data yang harus diperbarui
            if update_data:
                clients_collection.update_one({"_id": ObjectId(client_id)}, {"$set": update_data})
                projection = {"_id": False}
                result = clients_collection.find_one({"_id": ObjectId(client_id)}, projection=projection)

            return {"IsError": False, "Output": "Data Updated Successfully", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.delete("/client-delete", tags=["Clients"], dependencies=[Depends(get_current_user)])
def delete_client(client_id: str, 
    roles: str = Depends(get_current_user),    
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):
    # Decode the URL-encoded parameter
    if "sadmin" in roles:
        
        obj_id = ObjectId(client_id)

        clients = clients_collection.find_one({"_id": obj_id})
        if clients is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})
        
        clients_collection.delete_one({"_id": obj_id})
        # Hapus tenant berdasarkan tenant_id yang sama
        for collection in [accounts_collection, campaigns_collection, metrics_collection, settings_collection, history_collection]:
            collection.delete_many({"client_id": str(obj_id)})

        return {"IsError": False, "Output": "Data Deleted Successfully"}
    elif "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(client_id)
            # Now you can use the decoded "id" parameter in your database query
            clients = clients_collection.find_one({"_id": obj_id, "tenant_id": perusahaan})
            if clients is None:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})
            
            clients_collection.delete_one({"_id": obj_id, "tenant_id": perusahaan})
            # Hapus tenant berdasarkan tenant_id yang sama
            for collection in [accounts_collection, campaigns_collection, metrics_collection, settings_collection, history_collection]:
                collection.delete_many({"client_id": str(obj_id)})

            return {"IsError": False, "Output": "Data Deleted Successfully"}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permission for this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

    
@app.get("/client-by-id", tags=["Clients"])
def get_client(
    client_id: str,
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        obj_id = ObjectId(client_id)
        # Implementasi endpoint tanpa dependensi
        clients = list(clients_collection.find({"_id": obj_id,"tenant_id": tenantId}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Client Data by Id: {client_id}", "Data": clients}
    
    if "staff" in roles or "admin" in roles or "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(client_id)
            # Implementasi endpoint tanpa dependensi
            clients = list(clients_collection.find({"_id": obj_id,"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Client Data by Id: {client_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/client-by-tenant", tags=["Clients"])
def get_all_clients(    
    roles: str = Depends(get_current_user),
    user_id: str = Depends(get_current_user_user_id), 
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id), 
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin")):

    if "sadmin" in roles:
        # Check if tenantId is provided
        if tenantId:
            # Implementasi endpoint dengan dependensi tenantId
            clients = list(clients_collection.find({"tenant_id": tenantId}, {"password": 0}))
        else:
            # Implementasi endpoint tanpa dependensi tenantId (retrieve all data)
            clients = list(clients_collection.find({}, {"password": 0}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Client Data by TenantId: {tenantId}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(clients_collection.find({"tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Client Data by TenantId: {tenant_id}", "Data": clients}
        
    if "client" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            # Implementasi endpoint tanpa dependensi
            clients = list(clients_collection.find({"_id": ObjectId(user_id), "tenant_id": tenant_id}))

            # Mengubah format ObjectId ke string untuk respons
            for client in clients:
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Client Data by TenantId: {tenant_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


# CODING TENANT


@app.post("/tenant-create", tags=["Tenant"], dependencies=[Depends(get_current_user)])
def tenant_create(
    company: str = Form(...),
    address: str = Form(...),
    email: str = Form(...),
    contact: str = Form(...),
    language: str = Form(...),
    culture: str = Form(..., description="example = en_US, id_ID"),
    input_timezone: str = Form(...),
    currency: str = Form(...),
    currency_position: bool = Form(...),
    roles: str = Depends(get_current_user)
):
    contact = contact.replace("-", "").replace(" ", "")
    culture = culture.replace("-", "_")
    currency_symbol = currency.replace(" ", "").split("-")[0].strip()

    if "sadmin" in roles:
        # Cari data tenant berdasarkan nama tenant
        nama_data = tenant_collection.find_one({"company": company})
        if nama_data is not None:
            raise HTTPException(status_code=404, detail="Company Name already in use")
        
        # Dapatkan timestamp saat ini dalam UTC
        current_time_utc = datetime.now(utc)

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")
        
        tenant = {
            "company": company.upper(),
            "address": address,
            "email": email,
            "contact": contact,
            "language": language,
            "culture": culture,
            "subscription": False,
            "currency": currency_symbol,
            "currency_position": currency_position,
            "timestamp_create": localized_time,  # Format zona waktu sebagai string
            "timezone_name": input_timezone  # Format zona waktu sebagai string
        }

        insert_result = tenant_collection.insert_one(tenant)
        projection = {"_id": False}
        result = tenant_collection.find_one({"_id": insert_result.inserted_id}, projection=projection)
        
        return {"IsError": False, "Output": "Registration Successfully", "Data": result }
    else:
        raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "You do not have permission to access this endpoint", "Output": ""})
    
@app.put("/tenant-edit", tags=["Tenant"], dependencies=[Depends(get_current_user)])
def edit_tenant(
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin"),
    company: str = Form(None),
    address: str = Form(None),
    email: str = Form(None),
    contact: str = Form(None),
    language: str = Form(None),
    culture: str = Form(None, description="example = en_US, id_ID"),
    input_timezone: str = Form(None),
    currency: str = Form(None),
    currency_position: bool = Form(None),
    roles: str = Depends(get_current_user),
    perusahaan: str = Depends(get_current_user_perusahaan), 
    tenant_id: str = Depends(get_current_user_tenant_id)):

    if "sadmin" in roles:
        # Periksa apakah Clients ada dalam database
        existing_clients = tenant_collection.find_one({"_id": ObjectId(tenantId)})
        if not existing_clients:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Tenant tidak ditemukan", "Output": ""})

        current_time_utc = datetime.now(utc)

        # Ambil zona waktu dari data sebelumnya jika input_timezone kosong
        if not input_timezone:
            input_timezone = existing_clients.get("timezone_name", "UTC")

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

        update_data = {}
        if company is not None:
            update_data["company"] = company.upper()
            for collection in [user_collection, clients_collection, accounts_collection, campaigns_collection, metrics_collection, settings_collection, history_collection]:
                collection.update_many({"tenant_id": str(tenantId)}, {"$set": {"company_name": company.upper()}})
        if address is not None:
            update_data["address"] = address
        if email is not None:
            update_data["email"] = email
        if contact is not None:
            update_data["contact"] = contact.replace("-", "").replace(" ", "")
        if language is not None:
            update_data["language"] = language
        if culture is not None:
            update_data["culture"] = culture.replace("-", "_")
        if currency is not None:
            currency_symbol = currency.replace(" ", "").split("-")[0].strip()
            update_data["currency"] = currency_symbol
        if currency_position is not None:
            update_data["currency_position"] = currency_position

        update_data["timestamp_update"] = localized_time  # Update zona waktu
        update_data["timezone_name"] = input_timezone  # Update zona waktu

        # Lakukan pembaruan data jika ada data yang harus diperbarui
        if update_data:
            tenant_collection.update_one({"_id": ObjectId(tenantId)}, {"$set": update_data})
            projection = {"_id": False}
            result = tenant_collection.find_one({"_id": ObjectId(tenantId)}, projection=projection)

        return {"IsError": False, "Output": "Data Updated Successfully", "Data": [result]}

    elif "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            existing_clients = tenant_collection.find_one({"_id": ObjectId(tenant_id)})
            if not existing_clients:
                raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})
            
            current_time_utc = datetime.now(utc)

            if not input_timezone:
                input_timezone = existing_clients.get("timezone_name", "UTC")

            try:
                user_timezone = timezone(input_timezone)
                localized_time = current_time_utc.astimezone(user_timezone)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

            # Update data Clients jika nilai yang baru diberikan
            update_data = {}
            if company is not None:
                update_data["company"] = company.upper()
                # Update nama di koleksi lainnya
                for collection in [user_collection, clients_collection, accounts_collection, campaigns_collection, metrics_collection, settings_collection, history_collection]:
                    collection.update_many({"tenant_id": str(tenant_id)}, {"$set": {"company_name": company.upper()}})
            if address is not None:
                update_data["address"] = address
            if email is not None:
                update_data["email"] = email
            if contact is not None:
                update_data["contact"] = contact.replace("-", "").replace(" ", "")
            if language is not None:
                update_data["language"] = language
            if culture is not None:
                update_data["culture"] = culture.replace("-", "_")
            if currency is not None:
                currency_symbol = currency.replace(" ", "").split("-")[0].strip()
                update_data["currency"] = currency_symbol
            if currency_position is not None:
                update_data["currency_position"] = currency_position

            update_data["timestamp_update"] = localized_time   # Update zona waktu
            update_data["timezone_name"] = input_timezone  # Update zona waktu

            # Lakukan pembaruan data jika ada data yang harus diperbarui
            if update_data:
                tenant_collection.update_one({"_id": ObjectId(tenant_id)}, {"$set": update_data})
                projection = {"_id": False}
                result = tenant_collection.find_one({"_id": ObjectId(tenant_id)}, projection=projection)

            return {"IsError": False, "Output": "Data Updated Successfully", "Data": result}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.put("/tenant-subscription", tags=["Tenant"], dependencies=[Depends(get_current_user)])
def tenant_change_subscription(
    tenantId: str = Query(None, description="Hanya Untuk SuperAdmin"),
    subscription: bool = Form(None),
    roles: str = Depends(get_current_user)):

    if "sadmin" in roles:
        # Periksa apakah Clients ada dalam database
        existing_clients = tenant_collection.find_one({"_id": ObjectId(tenantId)})
        if not existing_clients:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Tenant tidak ditemukan", "Output": ""})

        current_time_utc = datetime.now(utc)

        input_timezone = existing_clients.get("timezone_name", "UTC")

        try:
            user_timezone = timezone(input_timezone)
            localized_time = current_time_utc.astimezone(user_timezone)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

        # Update data Clients jika nilai yang baru diberikan
        update_data = {}
        if subscription is not None:
            update_data["subscription"] = subscription

        update_data["timestamp_update"] = localized_time  # Update zona waktu
        update_data["timezone_name"] = input_timezone  # Update zona waktu

        if update_data:
            tenant_collection.update_one({"_id": ObjectId(tenantId)}, {"$set": update_data})
            projection = {"_id": False}
            result = tenant_collection.find_one({"_id": ObjectId(tenantId)}, projection=projection)

        return {"IsError": False, "Output": "Data Updated Successfully", "Data": [result]}

    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})
    
@app.delete("/tenant-delete", tags=["Tenant"], dependencies=[Depends(get_current_user)])
def tenant_delete(tenant_id: str, 
    roles: str = Depends(get_current_user)):
    if "sadmin" in roles:
        
        obj_id = ObjectId(tenant_id)

        # Now you can use the decoded "id" parameter in your database query
        clients = tenant_collection.find_one({"_id": obj_id})
        if clients is None:
            raise HTTPException(status_code=404, detail={"IsError": True, "ErrNum": 404, "ErrMsg": "Client tidak ditemukan", "Output": ""})
        
        tenant_collection.delete_one({"_id": obj_id})

        # Hapus tenant berdasarkan tenant_id yang sama
        for collection in [user_collection, clients_collection, accounts_collection, campaigns_collection, metrics_collection, settings_collection, history_collection]:
            collection.delete_many({"tenant_id": str(obj_id)})

        return {"IsError": False, "Output": "Tenant berhasil dihapus"}
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/tenant-by-id", tags=["Tenant"])
def tenant_get(
    tenantId: str = Query(None,description="Hanya Untuk SuperAdmin" ),
    user_id: str = Depends(get_current_user_user_id), 
    roles: str = Depends(get_current_user),
    tenant_id: str = Depends(get_current_user_tenant_id), 
    perusahaan: str = Depends(get_current_user_perusahaan)):

    if "sadmin" in roles:
        obj_id = ObjectId(tenantId)
        # Implementasi endpoint tanpa dependensi
        clients = list(tenant_collection.find({"_id": obj_id}))

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_user_culture(user_id)
            timezone_name = get_user_timezone(user_id)
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["timestamp_create"], timezone_name
                )
                client["timestamp_create"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Tenant Data by Id: {tenantId}", "Data": clients}
    
    if "staff" in roles or "admin" in roles:
        tenant_block = tenant_collection.find_one({"_id": ObjectId(perusahaan)})
        if tenant_block is not None:
            block = tenant_block["subscription"]
            if block == False:
                raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your Company has been blocked", "Output": ""})
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "Your company does not have access", "Output": ""})
        if tenant_id == perusahaan:
            obj_id = ObjectId(tenant_id)
            # Implementasi endpoint tanpa dependensi
            clients = list(tenant_collection.find({"_id": obj_id}))

            for client in clients:
                # Ubah format timestamp_create sesuai culture dan timezone
                culture = get_user_culture(user_id)
                timezone_name = get_user_timezone(user_id)
                
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_create"], timezone_name
                    )
                    client["timestamp_create"] = format_datetime(
                        localized_time, locale=culture
                    )
                    
                # Ubah format timestamp_update jika ada, sesuai culture dan timezone
                if "timestamp_update" in client:
                    if culture and timezone_name:
                        localized_time = convert_timestamp_to_timezone(
                            client["timestamp_update"], timezone_name
                        )
                        client["timestamp_update"] = format_datetime(
                            localized_time, locale=culture
                        )
                
                # Mengubah format ObjectId ke string untuk respons
                client["_id"] = str(client["_id"])

            return {"IsError": False, "Output": f"Account Data by Id: {tenant_id}", "Data": clients}
        else:
            raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have permission to access this Company", "Output": ""})
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})

@app.get("/tenant-get-all", tags=["Tenant"])
def tenant_get_all(    
    user_id: str = Depends(get_current_user_user_id), 
    roles: str = Depends(get_current_user)):

    if "sadmin" in roles:
        # Implementasi endpoint tanpa dependensi
        clients = list(tenant_collection.find())

        # Mengubah format ObjectId ke string untuk respons
        for client in clients:
            # Ubah format timestamp_create sesuai culture dan timezone
            culture = get_user_culture(user_id)
            timezone_name = get_user_timezone(user_id)
            
            if culture and timezone_name:
                localized_time = convert_timestamp_to_timezone(
                    client["timestamp_create"], timezone_name
                )
                client["timestamp_create"] = format_datetime(
                    localized_time, locale=culture
                )
                
            # Ubah format timestamp_update jika ada, sesuai culture dan timezone
            if "timestamp_update" in client:
                if culture and timezone_name:
                    localized_time = convert_timestamp_to_timezone(
                        client["timestamp_update"], timezone_name
                    )
                    client["timestamp_update"] = format_datetime(
                        localized_time, locale=culture
                    )
            
            # Mengubah format ObjectId ke string untuk respons
            client["_id"] = str(client["_id"])

        return {"IsError": False, "Output": f"Tenant Data", "Data": clients}
    else:
        raise HTTPException(status_code=403, detail={"IsError": True, "ErrNum": 403, "ErrMsg": "You do not have access permissions for this endpoint", "Output": ""})


@app.get("/timezone", response_model=list, tags=["For Select Front End"])
def get_all_timezones():
    timezones = list(timezone_collection.find({}, {"_id": 0}).sort("timezone", 1))

    timezone_list = [{"timezone": timezone["timezone"]} for timezone in timezones]

    return timezone_list

@app.get("/currency", response_model=list, tags=["For Select Front End"])
def get_all_currency():
    currencies = list(currency_collection.find({}, {"_id": 0}).sort("name", 1))

    # Concatenate symbol and name with a separator
    formatted_currencies = [{"currency": f"{currency['symbol']}  -  {currency['name']}"} for currency in currencies]

    return formatted_currencies
    
@app.get("/culture", response_model=list, tags=["For Select Front End"])
def get_all_culture():
    timezones = list(culture_collection.find({}, {"_id": 0}).sort("country", 1))   
    return timezones

@app.put("/metrics-hitung", tags=["Alat"])
def metrics_hitung(
    campaign_id: str,
    clicks: int = Form(..., description="150000"),
    lpview: int = Form(..., description="clicks > '95000'"),
    catc: int = Form(..., description="lpview > '25000'"),
    ctview: int = Form(..., description="10000"),
    results: int = Form(..., description="750"),
    amountspent: int = Form(..., description="4500000"),
    reach: int = Form(..., description="97000"),
    impressions: int = Form(..., description="230000"),
    delivery: float = Form(..., description="85"),
    leads: int = Form(..., description="220"),
    purchase: int = Form(..., description="7500000"),
    cpc: float = Form(..., description="3000")
    # frequency: float = Form(..., description="Impressions/Reach"),
    # ctr: float = Form(..., description="(Link Click/impressions) * 100"),
    # oclp: float = Form(..., description="30.5"),
    # cpr: int = Form(..., description="Amount Spent/Result"),
    # cpm: int = Form(..., description="amountspent/(impressions/1000)"),
    # roas: float = Form(..., description="purchase/amountspent"),
    # # realroas: float = Form(..., description="3.1"),
    # roles: str = Depends(get_current_user), 
    # perusahaan: str = Depends(get_current_user_perusahaan), 
    # tenant_id: str = Depends(get_current_user_tenant_id), 
):
    campaign_metrics = metrics_collection.find_one({"campaign_id": campaign_id})
    if not campaign_metrics:
        raise HTTPException(status_code=404, detail="Campaign & Metrics not found")
    campaign_data = campaigns_collection.find_one({"_id": ObjectId(campaign_id)})
    if not campaign_data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    input_timezone = campaign_data["timezone_name"]

    current_time_utc = datetime.now(utc)

    try:
        user_timezone = timezone(input_timezone)
        localized_time = current_time_utc.astimezone(user_timezone)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid timezone: {e}")

    frequency_value = impressions/reach
    rounded_frequency = round(frequency_value, 1)  # Membulatkan ke satu angka dibelakang koma

    # Hitung rar, cpc, ctr, oclp, cpr, atc, roas, dan realroas
    rar = (reach / amountspent) 
    rounded_rar = round(rar, 1)

    oclp = (lpview / clicks) * 100
    rounded_oclp = round(oclp, 1)

    ctr = (clicks / impressions) * 100
    rounded_ctr = round(ctr, 1)

    rroas = purchase / amountspent
    rounded_rroas = round(rroas, 1)

    ratc = (catc / lpview) * 100
    rounded_atc = round(ratc, 1)

    roas = purchase / amountspent
    rounded_roas = round(roas, 1)

    cpr = int(amountspent / results)
    cpm = int(amountspent / (impressions/1000))

    updated_data = {
        "campaign_id": campaign_id,
        "clicks": clicks,
        "lpview": lpview,
        "ctview": ctview,
        "results": results,
        "amountspent": amountspent,
        "reach": reach,
        "impressions": impressions,
        "purchase": purchase,
        "delivery": delivery,
        "frequency": rounded_frequency,
        "rar": rounded_rar,
        "cpc": cpc,
        "ctr": rounded_ctr,
        "oclp": rounded_oclp,
        "cpr": cpr,
        "leads": leads,
        "cpm": cpm,
        "atc": rounded_atc,
        "roas": rounded_roas,
        "realroas": rounded_rroas,
        "company_name": campaign_data["company_name"],
        "tenant_id": campaign_data["tenant_id"],
        "client_id": campaign_data["client_id"],
        "account_id": campaign_data["account_id"]
    }
    updated_data["timestamp_update"] = localized_time


    if updated_data:
        metrics_collection.update_one({"campaign_id": campaign_id}, {"$set": updated_data})
        projection = {"_id": False}
        result = metrics_collection.find_one({"campaign_id": campaign_id}, projection=projection)

    history_data = {
        "campaign_id": campaign_id,
        "clicks": clicks,
        "lpview": lpview,
        "ctview": ctview,
        "results": results,
        "amountspent": amountspent,
        "reach": reach,
        "impressions": impressions,
        "purchase": purchase,
        "delivery": delivery,
        "frequency": rounded_frequency,
        "rar": rounded_rar,
        "cpc": cpc,
        "ctr": rounded_ctr,
        "oclp": rounded_oclp,
        "cpr": cpr,
        "leads": leads,
        "cpm": cpm,
        "atc": rounded_atc,
        "roas": rounded_roas,
        "realroas": rounded_rroas,
        "company_name": campaign_data["company_name"],
        "tenant_id": campaign_data["tenant_id"],
        "client_id": campaign_data["client_id"],
        "account_id": campaign_data["account_id"]
    }
    history_data["timestamp_update"] = localized_time

    history_collection.insert_one(history_data)

    return {"IsError": False, "Output": "Metrics Successfully edited", "Data": result}

if __name__ == "__main__":
    app.run(debug=True)
