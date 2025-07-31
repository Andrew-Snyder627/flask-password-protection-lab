# Password Protection Lab

## Introduction

In this lab, you'll implement a secure authentication system that uses password hashing,
sessions, and route access control to manage user login and logout. This brings together
all the concepts you’ve learned about authentication so far, but with a critical
enhancement: users will now verify their identity using a password, and that password
will be safely hashed and stored in the database.

Plaintext password storage is one of the most dangerous vulnerabilities in any web
application. Instead of storing passwords directly, we’ll use Flask-Bcrypt to generate
one-way encrypted hashes, which can be validated without ever revealing the original
password.

You’ll build the full login workflow: signing up new users, verifying credentials on login,
checking whether a session is active, and logging users out. All of this will happen on the
Flask backend, while the provided React frontend will automatically reflect the user’s
authenticated state.

By the end of this lab, you’ll have implemented a secure, production-ready authentication
system using password hashing and session-based login—essential skills for any backend
developer working on user-facing applications.

## Tools & Resources

- [GitHub Repo](https://github.com/learn-co-curriculum/flask-password-protection-lab)
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/en/1.0.1/)

## Set Up

There is some starter code in place for a Flask API backend and a React frontend.
To get set up, run:

```console
$ pipenv install && pipenv shell
$ npm install --prefix client
$ cd server
$ flask db upgrade head
```

You can work on this lab by running the tests with `pytest -x`. It will also be
helpful to see what's happening during the request/response cycle by running the
app in the browser. You can run the Flask server with:

```console
$ python app.py
```

And you can run React in another terminal with:

```console
$ npm start --prefix client
```

You don't have to make any changes to the React code to get this lab working.

## Instructions

### Task 1: Define the Problem

Our app has three pages:

1. A signup page, where the user enters their username, password, and password
   confirmation.
2. A login page, where the user submits their username and password and are then
   logged in.
3. A user homepage, which says, "Welcome, ${username}!"

Users should not be able to log in if they enter an incorrect password.

> **Note: we're not covering password validations in this lab, so don't worry
> about those. Password validation is hard to get right anyway — it's
> surprisingly easy to produce rules that decrease password security rather than
> enhance it.**

### Task 2: Determine the Design

We need to implement a way for users to sign up, log in, and log out with secure
passwords.

To complete the lab and get the tests passing, you will need to:

- Add methods to the User model to protect and set the password_hash property and
  authenticate a user with their password.

- Create a `Signup` resource with a `post()` method that responds to a
  `POST /signup` request. It should: create a new user; save their hashed
  password in the database; save the user's ID in the session object; and return
  the user object in the JSON response.

- Create a `CheckSession` resource with a `get()` method that responds to a
  `GET /check_session` request. If the user is authenticated, return the user
  object in the JSON response. Otherwise, return an empty response with a 204
  status code.

- Create a `Login` resource with a `post()` method for logging in that
  responds to a `POST /login` request and returns the user as JSON.
- Create a `Logout` resource with a `delete()` method for logging out
  that responds to a `DELETE /logout` request.

### Task 3: Develop, Test, and Refine the Code

#### Step 1: Protect the `password_hash` Property

In the User model, add logic to protect the password_property by raising an Exception.

```python
# Build method to protect password_hash property
@hybrid_property
def password_hash(self):
    pass
```

#### Step 2: Use Bcrypt to Hash the Password

In the User model, use `bcrypt.generate_password_hash` to set the property.

```python
# Build method to set password hash property using bcrypt.generate_password_hash()
@password_hash.setter
def password_hash(self, password):
    pass
```

#### Step 3: Use Bcrypt to Authenticate a User

In the User model, use `bcrypt.check_password_hash` to verify a user's password.

```python
# Build authenticate method that uses bcrypt.check_password_hash()
def authenticate(self, password):
    pass
```

There are no tests for these methods, but you can verify they're set up properly by
using `flask shell` and creating some users.

Once you have all methods created, commit your code.

#### Step 4: Create Signup Endpoint

Create `POST /signup` endpoint. Implement the following:

- Create a new user.
- Save user to db with their hashed password using bcrypt.
- Log the user in with sessions.
- Return the user object.

Test your logic with `pytest` and commit your code.

#### Step 5: Create Check Session Endpoint

Create `GET /check_session` endpoint. Implement the following:

- If the user is authenticated, return the user object in the JSON response.
- Else, return an empty response with a 204 status code.

Test your logic with `pytest` and commit your code.

#### Step 6: Create Login Endpoint

Create `POST /login` endpoint. Implement the following:

- Log the user in with sessions.
- Returns the user as JSON.

Test your logic with `pytest` and commit your code.

#### Step 7: Create Logout Endpoint

Create `DELETE /logout` endpoint. Implement the following:

- Log the user out with sessions.

Test your logic with `pytest` and commit your code.

#### Step 8: Commit and Push Git History

Once all tests are passing, `git commit` (if needed) and `git push` your final code
to GitHub:

```bash
git add .
git commit -m "final solution"
git push
```

If you created a separate feature branch, remember to open a PR on main and merge.

### Task 4: Document and Maintain

Optional Best Practice documentation steps:

- Add comments to the code to explain purpose and logic, clarifying intent and
  functionality of your code to other developers.
- Update README text to reflect the functionality of the application following
  https://makeareadme.com.
  - Add screenshot of completed work included in Markdown in README.
- Delete any stale branches on GitHub
- Remove unnecessary/commented out code
- If needed, update git ignore to remove sensitive data

## Submit your solution

CodeGrade will use the same test suite as the test suite included.

Once all tests are passing, commit and push your work using `git` to submit to
CodeGrade through Canvas.

---

## Password Protection & User Authentication

This project includes secure user authentication using hashed passwords and Flask sessions.

### Features Implemented

- **User Model Enhancements**

  - Passwords are securely hashed using `bcrypt` via a write-only `@hybrid_property`.
  - Direct access to the hashed password is blocked for safety.
  - A custom `.authenticate(password)` method verifies login attempts.

- **Session-Based Auth**

  - On successful login/signup, the user ID is stored in the session (`session['user_id']`).
  - Session data is used to persist login state across requests.

- **Implemented Routes**

| Method | Endpoint         | Description                                |
| ------ | ---------------- | ------------------------------------------ |
| POST   | `/signup`        | Registers a new user and logs them in      |
| POST   | `/login`         | Authenticates a user and starts a session  |
| DELETE | `/logout`        | Ends the session by clearing `user_id`     |
| GET    | `/check_session` | Returns the logged-in user's data (if any) |
| DELETE | `/clear`         | Resets all session data (dev use only)     |

### Security Measures

- Passwords are never stored or transmitted in plain text.
- `@hybrid_property` ensures password hashes cannot be retrieved.
- Session cookies are used to persist login state securely.

### Test Coverage

All tests passed:

- User creation and login at `/signup` and `/login`
- Session verification via `/check_session`
- Logout and session clearing at `/logout` and `/clear`

---

```bash
Example Signup:
POST /signup
{
  "username": "ash",
  "password": "pikachu"
}
```

```bash
Example Login:
POST /login
{
  "username": "ash",
  "password": "pikachu"
}
```

---

This concludes the Password Protection section of the lab!
