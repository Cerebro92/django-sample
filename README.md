# Django Coding Sample

In this repository you will find a basic project built on the Django Rest
Framework. The purpose of this project is just to get a feel for your personal
coding style and preferences.

There is only one app currently created in the project — `accounts`. This
contains some basic authentication models and functionality. You will need the
create user view to create a user on your local db.

### Task
Your task for this assignment is to implement a simple invitation system. We
would like for an existing user to be able to send an invite to someone who is
not yet a user. This consists of the following requirements:

1. A new model for invites including `email`, `first_name`, `last_name`, as well
as a unique `id` and a boolean `is_active`
2. An endpoint for an existing user to create an invite, the output of which
should simply print the `id` for the invite (don't worry about email sending)
3. An endpoint to accept an invite by `id` and create a new user. This should
additionally mark the invite as inactive
4. An endpoint to retrieve an invite's details given an `id`

How you organize this in the project structure is up to your own discretion.

### System Requirements
1. Python 3.10 or higher
2. PostgreSQL

### Installation
1. Create a virtual environment: `python3.10 -m venv venv`
2. Create `.env` file to load environment variables (secret key, db creds, etc.)
and start virtual environment
3. Load environment variables and activate virtual environment: `source .env`
4. Install requirements: `pip install -r requirements.txt`
5. Create postgres user: `createuser -d -P <username>`
6. Create postgrest database: `createdb -O <username> <dbname>`
7. Apply database migrations: `python manage.py migrate`

### Development
1. Activate the virtual environment: `source .env`
2. Start django server: `python manage.py runserver`

### Testing
1. Activate the virtual environment: `source .env`
2. Run all project tests: `python manage.py test`
3. Run app specific tests: `python manage.py test api.apps.<app name>`
