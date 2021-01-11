import uvicorn
from loguru import logger
from typing import Optional
from starlette.responses import RedirectResponse, Response
from fastapi import Depends, FastAPI, Request, status, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi_login import LoginManager
from fastapi_login.exceptions import InvalidCredentialsException

from server.app.database import database, users
from server.app.utils import verify_password

SECRET_KEY = "8c1d92746114dea8497b7c82f7da4231c71f0e0a4a6dc71af593d36b6303e16a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite://db/server.db"


class NotAuthenticatedException(Exception):
    pass


# these two argument are mandatory
def exc_handler(request, exc):
    return RedirectResponse(url='/login')


manager = LoginManager(SECRET_KEY, tokenUrl='/auth/token', use_cookie=True)
manager.not_authenticated_exception = NotAuthenticatedException

app = FastAPI()
app.add_exception_handler(NotAuthenticatedException, exc_handler)
app.mount("/sdk", StaticFiles(directory="templates/sdk"), name="static")
templates = Jinja2Templates(directory="templates")


@manager.user_loader
async def load_user(email: str):  # could also be an asynchronous function
    query = users.select().where(users.c.email == email)
    user = await database.fetch_one(query)
    return user


@app.get("/current_user")
async def current_user(email: Optional[str] = Cookie(None)):
    return {
        "status": 0,
        "msg": "",
        "data": {'email': email}
    }


@app.post("/auth/token")
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await load_user(form_data.username)
    if not user:
        raise InvalidCredentialsException
    elif not verify_password(form_data.password, user.hashed_password):
        raise InvalidCredentialsException
    access_token = manager.create_access_token(
        data=dict(sub=user.email)
    )
    manager.set_cookie(response, access_token)
    response.set_cookie(key="email", value=user.email)
    result = {
        "status": 0,
        "msg": "",
        "data": {'access_token': access_token, 'token_type': 'bearer'}
    }
    response.status_code = status.HTTP_201_CREATED
    return result


@app.post("/cookie/clear")
async def clear_cookie(response: Response):
    response.set_cookie(key="access-token", value="")
    response.set_cookie(key="email", value="")
    response.status_code = status.HTTP_201_CREATED
    result = {
        "status": 0,
        "msg": "",
        "data": {'clear_access_token': 'true'}
    }
    return result


@app.get("/")
async def root(request: Request, current_user=Depends(manager)):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, log_level="info")
