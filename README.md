User FastAPI

Prerequisites

Python version >= 3.10

Clone the repository:

git clone https://github.com/Naveen4200/User_fast_api.git

Create a new environment.

Install dependencies:

python.exe -m pip install -U pip

pip install -r ./requirements.txt

Turn on your local server and create a database named "test".

Run the code using the following command in the terminal:

uvicorn main:app --reload

Open your browser and navigate to http://127.0.0.1:8000.

To access API documentation, add "/docs" to the URL in your browser:
http://127.0.0.1:8000/docs

Additional Notes

Ensure Python version is 3.10 or higher.

Make sure to create a database named "test" before running the code.

The API documentation can be accessed at the "/docs" endpoint after running the code.
