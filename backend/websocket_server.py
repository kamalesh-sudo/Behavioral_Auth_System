import asyncio
import websockets
import json
import logging
import os
import sys
from ml.behavioral_analyzer import BehavioralAnalyzer
from datetime import datetime

# Allow importing the new FastAPI package when running from backend/.
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from app.config import get_settings
from app.database import AuthDatabase
from app.security import verify_access_token

AUTH_TOKEN = os.environ.get("AUTH_TOKEN")

class BehavioralWebSocketServer:
    def __init__(self):
        settings = get_settings()
        self.settings = settings
        self.analyzer = BehavioralAnalyzer()
        self.db = AuthDatabase(settings.db_path)
        # Ensure models directory exists
        if not os.path.exists('models'):
            os.makedirs('models')
        self.analyzer.load_models()
        self.connected_clients = set()
        self.user_sessions = {}
        
        if not self.analyzer.is_trained:
            print("Models not found or not trained. Training with dummy data...")
            self._train_initial_models()

    async def terminate_session(self, session_id, user_id, risk_score, reason):
        payload = {
            "type": "session_terminated",
            "sessionId": session_id,
            "userId": user_id,
            "riskScore": risk_score,
            "reason": reason,
            "blocked": True,
            "timestamp": datetime.now().isoformat(),
        }

        ws = self.user_sessions.get(session_id, {}).get("websocket", None)
        try:
            if ws:
                await ws.send(json.dumps(payload))
        except Exception:  # pylint: disable=broad-except
            pass

        if ws:
            try:
                await ws.close(code=1008, reason="Session terminated due to behavioral anomaly")
            except Exception:  # pylint: disable=broad-except
                pass

        self.user_sessions.pop(session_id, None)

    def _train_initial_models(self):
        # Generate some dummy data for initial training
        dummy_data = []
        for i in range(5):
            dummy_keystroke = [
                {'type': 'keydown', 'keyCode': 65, 'key': 'a', 'timestamp': 100 + i * 10},
                {'type': 'keyup', 'keyCode': 65, 'key': 'a', 'timestamp': 150 + i * 10, 'dwellTime': 50},
                {'type': 'keydown', 'keyCode': 66, 'key': 'b', 'timestamp': 200 + i * 10},
                {'type': 'keyup', 'keyCode': 66, 'key': 'b', 'timestamp': 250 + i * 10, 'dwellTime': 50},
            ]
            dummy_mouse = [
                {'type': 'mousemove', 'x': 100 + i, 'y': 100 + i, 'timestamp': 100 + i * 5},
                {'type': 'mousemove', 'x': 110 + i, 'y': 110 + i, 'timestamp': 110 + i * 5},
                {'type': 'click', 'x': 110 + i, 'y': 110 + i, 'button': 0, 'timestamp': 120 + i * 5},
            ]
            dummy_data.append({
                'user_id': f'user_{i}',
                'behavioral_data': {
                    'keystrokeData': dummy_keystroke,
                    'mouseData': dummy_mouse
                }
            })
        
        self.analyzer.train_global_model(dummy_data)
        print("Initial models trained and saved.")

    async def register_client(self, websocket, path=None):
        """Register new client connection"""
        try:
            # The first message should be an authentication token.
            auth_message = await websocket.recv()
            auth_data = json.loads(auth_message)
            token = (auth_data.get("token") or "").strip()
            if not token:
                await websocket.close(code=1008, reason="Authentication token missing")
                return
            try:
                claims = verify_access_token(token, self.settings)
            except (ValueError, RuntimeError):
                # Legacy fallback for existing clients still using static token.
                if not AUTH_TOKEN or token != AUTH_TOKEN:
                    await websocket.close(code=1008, reason="Invalid authentication token")
                    return
                claims = {"sub": None, "user_id": None}
            setattr(websocket, "auth_username", claims.get("sub"))
            setattr(websocket, "auth_user_id", claims.get("user_id"))
        except (websockets.exceptions.ConnectionClosed, json.JSONDecodeError):
            await websocket.close(code=1008, reason="Authentication failed")
            return

        self.connected_clients.add(websocket)
        print(f"Client connected: {websocket.remote_address}")
        
        try:
            async for message in websocket:
                await self.process_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.connected_clients.discard(websocket)
            print(f"Client disconnected: {websocket.remote_address}")
    
    async def process_message(self, websocket, message):
        """Process incoming behavioral data"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            claimed_user = data.get("userId")
            auth_user = getattr(websocket, "auth_username", None)
            if auth_user and claimed_user and auth_user != claimed_user:
                await websocket.close(code=1008, reason="User mismatch for authenticated token")
                return
            
            if message_type == 'behavioral_data':
                await self.handle_behavioral_data(websocket, data)
            elif message_type == 'user_authentication':
                await self.handle_user_authentication(websocket, data)
            elif message_type == 'feedback':
                await self.handle_feedback(websocket, data)
                
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON format received: {message}")
            await websocket.send(json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logging.error(f"Error processing message: {e}", exc_info=True)
            await websocket.send(json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def handle_behavioral_data(self, websocket, data):
        """Handle incoming behavioral data"""
        user_id = data.get('userId')
        session_id = data.get('sessionId')
        keystroke_data = data.get('keystrokeData', [])
        mouse_data = data.get('mouseData', [])

        if self.db.is_user_blocked(user_id):
            await self.terminate_session(
                session_id=session_id,
                user_id=user_id,
                risk_score=1.0,
                reason="User account is blocked due to anomaly detection",
            )
            return
        
        # Analyze behavioral data
        risk_score = self.analyzer.analyze_real_time(
            keystroke_data, mouse_data, user_id
        )
        
        # Store session information
        self.user_sessions[session_id] = {
            'user_id': user_id,
            'websocket': websocket,
            'last_activity': datetime.now(),
            'risk_score': risk_score
        }

        # Save behavioral profile to database if user exists
        user_info = self.db.get_user(user_id)
        if user_info.get('success'):
            self.db.save_behavioral_profile(
                user_info['user']['id'],
                session_id,
                keystroke_data,
                mouse_data,
                risk_score
            )

        if risk_score >= self.settings.anomaly_block_threshold:
            block_reason = "Behavioral anomaly detected in real-time monitoring"
            self.db.block_user(user_id, session_id, risk_score, block_reason)
            await self.terminate_session(session_id, user_id, risk_score, block_reason)
            return
        
        # Send response
        response = {
            'type': 'analysis_result',
            'sessionId': session_id,
            'riskScore': risk_score,
            'timestamp': datetime.now().isoformat()
        }
        
        # Send alert if high risk
        if risk_score > self.settings.high_risk_threshold:
            response['alert'] = {
                'level': 'HIGH',
                'message': 'Unusual behavioral patterns detected',
                'recommended_action': 'Require additional authentication'
            }
        elif risk_score > 0.5:
            response['alert'] = {
                'level': 'MEDIUM',
                'message': 'Behavioral patterns slightly deviate from norm'
            }
            
        await websocket.send(json.dumps(response))

    async def handle_user_authentication(self, websocket, data):
        """Handle user authentication events"""
        user_id = data.get('userId')
        session_id = data.get('sessionId')
        logging.info(f"User authentication received: userId={user_id}, sessionId={session_id}")

        if self.db.is_user_blocked(user_id):
            await self.terminate_session(
                session_id=session_id,
                user_id=user_id,
                risk_score=1.0,
                reason="User account is blocked due to anomaly detection",
            )
            return
        
        # Create a new user profile if one doesn't exist
        if user_id not in self.analyzer.user_profiles:
            self.analyzer.create_user_profile(user_id, {
                'keystrokeData': [],
                'mouseData': []
            })
            
        await websocket.send(json.dumps({
            'type': 'authentication_success',
            'userId': user_id
        }))

    async def handle_feedback(self, websocket, data):
        """Handle feedback from the user"""
        user_id = data.get('userId')
        session_id = data.get('sessionId')
        feedback = data.get('feedback')
        behavioral_data = data.get('behavioralData')

        if self.db.is_user_blocked(user_id):
            await self.terminate_session(
                session_id=session_id,
                user_id=user_id,
                risk_score=1.0,
                reason="User account is blocked due to anomaly detection",
            )
            return
        
        # Update user profile based on feedback
        self.analyzer.update_user_profile(user_id, behavioral_data, feedback)
        
        await websocket.send(json.dumps({
            'type': 'feedback_received',
            'message': 'User profile updated'
        }))

async def main():
    server = BehavioralWebSocketServer()
    host = os.environ.get("WEBSOCKET_HOST", "localhost")
    port = int(os.environ.get("WEBSOCKET_PORT", 8765))

    async with websockets.serve(server.register_client, host, port):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
