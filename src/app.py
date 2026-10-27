"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import os
from pathlib import Path
import time

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

SESSION_COOKIE = "teacher_session"
SESSION_MAX_AGE = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def _session_secret():
    return os.environ.get("SESSION_SECRET")


def _teacher_credentials_configured():
    session_secret = _session_secret()
    return bool(
        os.environ.get("TEACHER_USERNAME")
        and os.environ.get("TEACHER_PASSWORD_HASH")
        and session_secret
        and len(session_secret) >= 32
    )


def _verify_teacher_password(password):
    try:
        salt, expected_hash = os.environ["TEACHER_PASSWORD_HASH"].split(":")
        salt_bytes = bytes.fromhex(salt)
        expected_bytes = bytes.fromhex(expected_hash)
    except (KeyError, ValueError):
        return False

    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, PASSWORD_HASH_ITERATIONS
    )
    return hmac.compare_digest(password_hash, expected_bytes)


def _create_session_token(username):
    issued_at = int(time.time())
    encoded_username = base64.urlsafe_b64encode(username.encode("utf-8")).decode("ascii")
    payload = f"{encoded_username}:{issued_at}"
    signature = hmac.new(
        _session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}:{signature}"


def _authenticated_teacher(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        encoded_username, issued_at, signature = token.rsplit(":", 2)
        issued_at = int(issued_at)
        username = base64.urlsafe_b64decode(encoded_username).decode("utf-8")
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Teacher sign-in required")

    if not _teacher_credentials_configured():
        raise HTTPException(
            status_code=503, detail="Teacher authentication is not configured"
        )

    payload = f"{encoded_username}:{issued_at}"
    expected_signature = hmac.new(
        _session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if (
        username != os.environ["TEACHER_USERNAME"]
        or not hmac.compare_digest(signature, expected_signature)
        or issued_at > time.time()
        or time.time() - issued_at > SESSION_MAX_AGE
    ):
        raise HTTPException(status_code=401, detail="Teacher sign-in required")
    return username

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/auth/session")
def get_auth_session(request: Request):
    try:
        username = _authenticated_teacher(request)
    except HTTPException as error:
        if error.status_code == 503:
            return {"authenticated": False, "configured": False}
        return {
            "authenticated": False,
            "configured": _teacher_credentials_configured(),
        }
    return {"authenticated": True, "configured": True, "username": username}


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response):
    if not _teacher_credentials_configured():
        raise HTTPException(
            status_code=503, detail="Teacher authentication is not configured"
        )
    username_matches = hmac.compare_digest(
        credentials.username, os.environ["TEACHER_USERNAME"]
    )
    password_matches = _verify_teacher_password(credentials.password)
    if not username_matches or not password_matches:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=_create_session_token(credentials.username),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=os.environ.get("COOKIE_SECURE", "true").lower() != "false",
        samesite="lax",
        path="/",
    )
    return {"message": "Signed in successfully"}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE, path="/", samesite="lax")
    return {"message": "Signed out successfully"}


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str,
                         _teacher: str = Depends(_authenticated_teacher)):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str,
                              _teacher: str = Depends(_authenticated_teacher)):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
