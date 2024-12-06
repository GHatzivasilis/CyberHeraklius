# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory to /app
WORKDIR .

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir flask-cors requests beautifulsoup4

# Install updates
#RUN apt-get update

# Install Hydra password cracking
RUN apt-get update && apt-get install -y \
    hydra \
    hydra-gtk \
    && rm -rf /var/lib/apt/lists/*

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["python", "app.py", "--SecOPERA_url", "http://127.0.0.1:8000"]
