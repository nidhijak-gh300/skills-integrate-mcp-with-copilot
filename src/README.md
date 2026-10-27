# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher sign-in for signing up and unregistering students
- Public viewing of activities and participant lists

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Configure teacher credentials and a session-signing secret in the environment. Generate a salted password hash and a random session secret:

   ```
   python -c "import getpass,hashlib,secrets; p=getpass.getpass('Teacher password: '); s=secrets.token_bytes(16); print(s.hex()+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),s,600000).hex())"
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Set the resulting values as `TEACHER_PASSWORD_HASH` and `SESSION_SECRET`, and set `TEACHER_USERNAME` to the teacher's username. Keep these values in your deployment's secret manager or environment configuration; do not commit them. For local HTTP development only, set `COOKIE_SECURE=false`. The default requires HTTPS for the session cookie.

3. Run the application:

   ```
   uvicorn app:app --app-dir src --reload
   ```

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                        | Get all activities and participant lists (public)        |
| GET    | `/auth/session`                                                      | Check whether a teacher is signed in                      |
| POST   | `/auth/login`                                                        | Sign in with configured teacher credentials              |
| POST   | `/auth/logout`                                                       | Sign out                                                  |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu`    | Sign up a student (teacher sign-in required)              |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teacher sign-in required)           |

`POST /auth/login` accepts a JSON body such as `{"username":"teacher","password":"..."}`.

Teacher sessions use a signed, HTTP-only, same-site cookie and expire after eight hours. If authentication is not configured, public activity viewing remains available but sign-in and registration changes are disabled.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
