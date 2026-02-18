from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.user_db import UserDatabase

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Initialize database
db = UserDatabase()

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        # Validate password strength
        if len(password) < 6:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 6 characters long'
            }), 400
        
        # Create user
        result = db.create_user(username, password)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'User registered successfully',
                'user_id': result['user_id'],
                'username': result['username']
            }), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/start-session', methods=['POST'])
def start_session():
    """Start a session for a user (create if not exists)"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        result = db.get_or_create_user(username, password)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        risk_score = data.get('risk_score', 0)
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        # Verify credentials
        result = db.verify_user(username, password)
        
        # Log login attempt
        db.log_login_attempt(
            username,
            result['success'],
            risk_score,
            request.remote_addr
        )
        
        if result['success']:
            # Check risk score
            if risk_score > 0.7:
                return jsonify({
                    'success': False,
                    'error': 'High behavioral risk detected. Additional authentication required.',
                    'risk_score': risk_score,
                    'requires_mfa': True
                }), 403
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user_id': result['user_id'],
                'username': result['username'],
                'risk_score': risk_score
            }), 200
        else:
            return jsonify(result), 401
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/behavioral-profile', methods=['POST'])
def save_behavioral_profile():
    """Save user's behavioral profile"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        session_id = data.get('session_id')
        keystroke_data = data.get('keystroke_data', [])
        mouse_data = data.get('mouse_data', [])
        risk_score = data.get('risk_score', 0)
        
        if not user_id or not session_id:
            return jsonify({
                'success': False,
                'error': 'User ID and session ID are required'
            }), 400
        
        result = db.save_behavioral_profile(
            user_id,
            session_id,
            keystroke_data,
            mouse_data,
            risk_score
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Behavioral profile saved successfully'
            }), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/user/<username>', methods=['GET'])
def get_user(username):
    """Get user information"""
    try:
        result = db.get_user_by_username(username)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/user/<int:user_id>/behavioral-history', methods=['GET'])
def get_behavioral_history(user_id):
    """Get user's behavioral history"""
    try:
        limit = request.args.get('limit', 10, type=int)
        result = db.get_user_behavioral_history(user_id, limit)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Behavioral Authentication API'
    }), 200

if __name__ == '__main__':
    # Create database directory if it doesn't exist
    os.makedirs('database', exist_ok=True)
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
