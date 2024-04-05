"""
MIT License

Copyright (c) 2023 Oviyan Gandhi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import json
from fastapi import FastAPI, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from os import environ
from typing import Annotated
from uuid import UUID
from .errors import *
from .types import *
from .database import Database
from .ratelimits import RateLimiter

class USACOAPI(FastAPI):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open("settings.json", "r") as f:
            self.settings: dict = json.load(f)
        db_url = environ.get("DATABASE_URL")
        if db_url:
            self.settings["database"]["dsn"] = db_url
        self.db = Database(self)
        self.limiter = RateLimiter("5 / 2 seconds")
        self.add_middleware(
            CORSMiddleware,
            allow_origins=["chrome-extension://jmlpdjciabnplpimhafibghkcpjckblh", "https://usaco.guide"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["*"],
        )

    def limit(self, interval: str):
        """Shorthand for USACOAPI.limiter.limit"""
        return self.limiter.limit(interval)

app = USACOAPI()

# Response handling

@app.exception_handler(APIException)
async def api_exception_handler(_, exc: APIException):
    return JSONResponse(status_code=exc.status_code, content={
        "success": False, "status": exc.status_code, "errors": exc.errors
    })

def success(**data):
    return JSONResponse(content=dict(success=True, status=200, **data))

# Security Functions

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def resolve_username(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    try:
        username = app.db.get_username(UUID(token))
    except ValueError:
        username = None
    if not username:
        raise APIException(status.HTTP_401_UNAUTHORIZED, [{
            "code": "INVALID_TOKEN",
            "description": "The token given is invalid"
        }])
    return username

# User Management

def verify_credentials(user: User | OptionalUser):
    errors: list[dict] = []
    if user.name is not None:
        if len(user.name) < 2:
            errors.append({
                "code": "SHORT_USERNAME",
                "description": "The username should be at least 2 characters long"
            })
        elif len(user.name) > 32:
            errors.append({
                "code": "LONG_USERNAME",
                "description": "The username should be at most 32 characters long"
            })
        elif app.db.user_exists(user.name):
            errors.append({
                "code": "USERNAME_TAKEN",
                "description": "User with the same name already exists"
            })
    if user.password is not None:
        if len(user.password) < 8:
            errors.append({
                "code": "SHORT_PASSWORD",
                "description": "The password should be at least 8 characters long"
            })
        elif len(user.password) > 64:
            errors.append({
                "code": "LONG_PASSWORD",
                "description": "The password should be at most 64 characters long"
            })
    if errors:
        raise APIException(status.HTTP_400_BAD_REQUEST, errors)
    return user

@app.post("/users")
@app.limit("3/day")
async def signup(user: Annotated[User, Depends(verify_credentials)], request: Request):
    """Signs up a new user for the service"""
    try:
        token = await app.db.signup(user.name, user.password)
        return success(token=token)
    except DuplicateError:
        raise APIException(status.HTTP_409_CONFLICT, [{
            "code": "USERNAME_TAKEN",
            "description": "The username is already taken."
        }])

@app.patch("/users")
@app.limit("5/hour")
async def update_user(
    username: Annotated[str, Depends(resolve_username)],
    new: Annotated[OptionalUser, Depends(verify_credentials)], request: Request
):
    """Updates the username and/or password of a user"""
    token = await app.db.update_user(username, new.name, new.password)
    return success(token=token)

@app.delete("/users")
@app.limit("1/day")
async def delete_user(username: Annotated[str, Depends(resolve_username)], request: Request):
    """Removes a user from the service"""
    await app.db.remove_user(username)
    return success()

# Token Handling

@app.post("/token")
@app.limit("5/minute")
async def get_token(user: User, request: Request):
    try:
        token_data = await app.db.get_token(user.name, user.password)
    except UnauthorizedError:
        raise APIException(status.HTTP_401_UNAUTHORIZED, [{
            "code": "USER_NOT_FOUND",
            "description": "User with given name and password not found"
        }]) from None
    return success(**token_data)

@app.delete("/token")
@app.limit("5/minute")
async def remove_token(username: Annotated[str, Depends(resolve_username)], request: Request):
    await app.db.remove_token(username)
    return success()

# User Data

@app.get("/user_data")
@app.limit("3 / 2 seconds")
async def user_data(username: Annotated[str, Depends(resolve_username)], request: Request):
    async with app.db.acquire() as conn:
        follows = await app.db.get_follows(username, conn=conn)
        progress = {}
        for tname in ["problems", "modules"]:
            progress[tname] = await app.db.get_progress(username, tname, conn=conn)
        follow_data = await app.db.get_follower_progress(username, conn=conn)
        follow_data["following"] = follows
    return success(
        userData=dict(username=username, progress=progress),
        followData=follow_data
    )

@app.get("/autocomplete")
@app.limit("1 / second")
async def autocomplete(username: Annotated[str, Depends(resolve_username)], name: str, request: Request):
    return success(users=app.db.autocomplete(name))

# Update Progress

@app.post("/problems")
@app.limit("2 / 3 seconds")
async def update_problem(
    username: Annotated[str, Depends(resolve_username)], progress: ProblemList, request: Request
):
    await app.db.update_progress(username, "problems", progress)
    return success()

@app.post("/modules")
@app.limit("2 / 3 seconds")
async def update_module(
    username: Annotated[str, Depends(resolve_username)], progress: ModuleList, request: Request
):
    await app.db.update_progress(username, "modules", progress)
    return success()

# Follow Management

@app.post("/follows")
@app.limit("2 / 5 seconds")
async def follow(
    username: Annotated[str, Depends(resolve_username)], follow: FollowRequest, request: Request
):
    if (username == follow.username):
        raise APIException(status.HTTP_400_BAD_REQUEST, [{
            "code": "CANNOT_FOLLOW_SELF",
            "description": "You cannot follow yourself"
        }])
    try:
        data = await app.db.follow(username, follow.username)
        return success(**data)
    except DuplicateError:
        raise APIException(status.HTTP_409_CONFLICT, [{
            "code": "ALREADY_FOLLOWING",
            "description": "You are already following this user."
        }])
    except UnknownUsernameError:
        raise APIException(status.HTTP_404_NOT_FOUND, [{
            "code": "USER_NOT_FOUND",
            "description": "The user you are trying to follow does not exist."
        }])

@app.delete("/follows")
@app.limit("2 / 5 seconds")
async def unfollow(
    username: Annotated[str, Depends(resolve_username)], follow: FollowRequest, request: Request
):
    await app.db.unfollow(username, follow.username)
    return success()