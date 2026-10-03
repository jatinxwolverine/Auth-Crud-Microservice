from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# --- Configuration ---
SECRET_KEY = "supersecretjwtkey_change_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="JWT Auth & CRUD Microservice",
    description="FastAPI service with JWT Authentication and CRUD operations",
    version="1.0.0",
)

# --- In-Memory Databases ---
users_db: Dict[str, dict] = {}
items_db: Dict[int, dict] = {}
item_id_counter = 1

# --- Pydantic Schemas ---
class UserRegister(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ItemCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float

class ItemResponse(ItemCreate):
    id: int
    owner: str

# --- Security Helpers ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password[:72])

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if username not in users_db:
        raise credentials_exception
    return username

# --- Authentication Routes ---
@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    users_db[user.username] = {
        "username": user.username,
        "password": get_password_hash(user.password[:72]),
    }
    return {"message": "User registered successfully"}

@app.post("/token", response_model=Token, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Protected CRUD Routes ---
@app.post("/items", response_model=ItemResponse, status_code=status.HTTP_201_CREATED, tags=["Items"])
def create_item(item: ItemCreate, current_user: str = Depends(get_current_user)):
    global item_id_counter
    item_record = {
        "id": item_id_counter,
        "title": item.title,
        "description": item.description,
        "price": item.price,
        "owner": current_user,
    }
    items_db[item_id_counter] = item_record
    item_id_counter += 1
    return item_record

@app.get("/items", response_model=List[ItemResponse], tags=["Items"])
def read_items(current_user: str = Depends(get_current_user)):
    return list(items_db.values())

@app.get("/items/{item_id}", response_model=ItemResponse, tags=["Items"])
def read_item(item_id: int, current_user: str = Depends(get_current_user)):
    if item_id not in items_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return items_db[item_id]

@app.put("/items/{item_id}", response_model=ItemResponse, tags=["Items"])
def update_item(item_id: int, item: ItemCreate, current_user: str = Depends(get_current_user)):
    if item_id not in items_db:
        raise HTTPException(status_code=404, detail="Item not found")
    if items_db[item_id]["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to edit this item")
    items_db[item_id].update(item.model_dump())
    return items_db[item_id]

@app.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Items"])
def delete_item(item_id: int, current_user: str = Depends(get_current_user)):
    if item_id not in items_db:
        raise HTTPException(status_code=404, detail="Item not found")
    if items_db[item_id]["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to delete this item")
    del items_db[item_id]
    return None