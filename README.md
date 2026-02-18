# Behavioral Authentication System

## About the Project

**Developed by:** Kamalesh S
**Company:** Elevate Labs
**Role:** Cybersecurity Intern (Project Phase)


## Project Overview

## Project Structure

```
behavioral-auth/
├── backend/
│   ├── api/
│   ├── auth/
│   ├── database/
│   ├── ml/
│   │   ├── behavioral_analyzer.py
│   │   └── feature_extractor.py
│   ├── models/
│   ├── utils/
│   ├── requirements.txt
│   └── websocket_server.py
├── data/
├── docs/
├── frontend/
│   ├── collector/
│   │   └── behavioral-collector.js
│   ├── dashboard/
│   │   ├── dashboard.js
│   │   ├── index.html
│   │   └── style.css
│   ├── extension/
│   ├── node_modules/
│   ├── package.json
│   ├── package-lock.json
│   └── server.js
├── models/
├── tests/
├── venv/
├── venv-3.9/
├── PROJECT_STATUS.md
└── README.md
```



This project implements a real-time Behavioral Authentication System designed to enhance security by continuously analyzing user keystroke and mouse dynamics. Unlike traditional authentication methods that rely solely on static credentials, this system builds a unique behavioral profile for each user and detects anomalies that might indicate unauthorized access or malicious activity.

The system comprises a Python-based backend for machine learning analysis and a JavaScript-based frontend for data collection and visualization.

## Features

*   **Real-time Behavioral Data Collection:** Captures keystroke dynamics (e.g., dwell time, flight time) and mouse dynamics (e.g., velocity, acceleration, movement patterns).
*   **Machine Learning-driven Analysis:** Utilizes `IsolationForest` for user-specific anomaly detection and `RandomForestClassifier` and `LSTM` for global behavioral pattern recognition.
*   **Dynamic Risk Scoring:** Assigns a real-time risk score based on deviations from established behavioral profiles.
*   **Alerting Mechanism:** Triggers alerts for high-risk behavioral patterns, suggesting additional authentication steps.
*   **User Profile Management:** Creates and updates individual user behavioral profiles.
*   **Web-based Dashboard:** Provides a visual interface to monitor real-time risk scores and alerts.

## Technologies Used

### Backend (Python)

*   **Flask:** Web framework for API endpoints.
*   **Websockets:** For real-time communication between frontend and backend.
*   **Scikit-learn:** For traditional machine learning models (e.g., IsolationForest, RandomForestClassifier).
*   **TensorFlow/Keras:** For deep learning models (LSTM) to analyze temporal behavioral sequences.
*   **NumPy & Pandas:** For data manipulation and numerical operations.
*   **SciPy:** For scientific computing and statistical analysis.

### Frontend (JavaScript/HTML/CSS)

*   **Node.js/Express:** To serve the frontend application.
*   **WebSockets API:** For real-time communication with the backend.
*   **Vanilla JavaScript:** For behavioral data collection and dashboard interactivity.

## Setup and Installation

Follow these steps to set up and run the project locally.

### 1. Clone the Repository

```bash
git clone https://github.com/iharishragav/Behavioral_Auth_System.git
cd behavioral-auth
```

### 2. Backend Setup (Python)

It is highly recommended to use a virtual environment.

```bash
# Create a virtual environment (if you don't have one)
python3 -m venv venv-3.9

# Activate the virtual environment
source venv-3.9/bin/activate

# Navigate to the backend directory
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Return to the project root
cd ..
```

### 3. Frontend Setup (Node.js)

```bash
# Navigate to the frontend directory
cd frontend

# Install Node.js dependencies
npm install

# Return to the project root
cd ..
```

### 4. Running the Application

#### Start the Backend Server

Open a new terminal, activate the Python virtual environment, and start the WebSocket server:

```bash
cd behavioral-auth/backend
source venv-3.9/bin/activate
python websocket_server.py
```

Leave this terminal open as the backend server runs in the foreground.

#### Start the Frontend Server

Open another new terminal, navigate to the frontend directory, and start the Express server:

```bash
cd behavioral-auth/frontend
npm start
```

## Usage

Once both the backend and frontend servers are running:

1.  Open your web browser and navigate to `http://localhost:3000` to access the Behavioral Authentication Dashboard.
2.  Interact with the page (move your mouse, type on your keyboard). The system will collect your behavioral data, send it to the backend for analysis, and update the real-time risk score on the dashboard.
3.  Observe the console in your browser's developer tools for logs related to data collection and WebSocket communication.

## Project Status and Future Enhancements

This project is currently in active development.

For detailed weekly updates on project progress, challenges, and next steps, please refer to the [Project Status Updates](PROJECT_STATUS.md) document.

Key areas for future enhancements include:

*   **Browser Extension:** Develop a browser extension to collect behavioral data across multiple websites.
*   **User Management:** Implement robust user registration, login, and profile management.
*   **Database Integration:** Integrate with a database (e.g., PostgreSQL, Redis) for persistent storage of user profiles and behavioral data.
*   **Advanced ML Models:** Explore more sophisticated machine learning and deep learning architectures for improved accuracy and real-time performance.
*   **Comprehensive Testing:** Develop a comprehensive suite of unit and integration tests.
*   **Deployment:** Prepare the application for production deployment.

## Contributing

Contributions are welcome! Please feel free to fork the repository, create pull requests, or open issues for bugs and feature requests.


"# BHA" 
