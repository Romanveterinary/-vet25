# -vet25
# VetAI-Expertise Project

This is the main web application for the VetAI-Expertise project. The complete system consists of three separate components:

1.  **Main Web App:** (This repository) - The primary user interface and backend built with Flask.
    * Link: `https://github.com/Romanveterinary/-vet25`
2.  **Telegram Bot:** The component responsible for chatbot interactions.
    * Link: `[ https://github.com/Romanveterinary/gemini-chat-backend.git]`
3.  **AI Logic Core:** A separate repository containing the core AI models and processing logic.
    * Link: `(https://github.com/Romanveterinary/--------------------------.git)]`

## How to run this application

1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`
3. Activate it: `source venv/bin/activate` (on Linux/Mac) or `venv\Scripts\activate` (on Windows).
4. Install dependencies: `pip install -r requirements.txt`
5. Initialize the database: `flask init-db`
6. Run the application: `flask run`
