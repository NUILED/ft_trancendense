FROM python:3.8-slim

# Set the working directory
WORKDIR /backend


COPY  . . 

# Install the dependencies

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

# Expose the port the app runs on

EXPOSE 8080

# Run the app
CMD ["sh", "-c", "python manage.py makemigrations && python manage.py migrate && python manage.py runserver 0.0.0.0:8080"]