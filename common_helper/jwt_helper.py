import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Request



def create_access_token(data: dict, expires_delta: timedelta = None, SECRET_KEY: str = "secret"):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=24))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def decode_access_token(token: str, SECRET_KEY: str = "secret"):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload['phone']
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"status": False, "message": "Token expired"}) 
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={"status": False, "message": "Invalid token"})




async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): 
        raise HTTPException(status_code=403, detail={"status": False, "message": "Authorization token missing"})       
    token = auth_header.split(" ")[1]
    return decode_access_token(token)
   
