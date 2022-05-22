release: python manage.py migrate
web: newrelic-admin run-program gunicorn api.wsgi:application --log-file -
