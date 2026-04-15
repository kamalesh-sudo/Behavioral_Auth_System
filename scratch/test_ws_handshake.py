import asyncio
import websockets
import json
import os

# Use the AUTH_TOKEN from environment if set, otherwise a known valid one for test
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzYyODM5OTQsImlhdCI6MTc3NjI3Njc5NCwic3ViIjoia2FtYWxlc2giLCJ0eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6MX0.vrlWkAD5X5Fg3R7A4Ov4wgQKXStZz6Ns6mPJdbOwh-g")

async def test_handshake():
    uri = "ws://localhost:5000/ws/behavioral?token=" + AUTH_TOKEN
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Handshake successful!")
            
            # The server expects an authentication message even if token is in query
            auth_payload = {
                "type": "user_authentication",
                "token": AUTH_TOKEN
            }
            await websocket.send(json.dumps(auth_payload))
            print("Sent authentication payload.")
            
            # Wait for any potential error or standard response
            try:
                # We expect no immediate error
                response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                print(f"Received response: {response}")
            except asyncio.TimeoutError:
                print("No immediate response received (expected if just listening).")
            
            # Send a behavioral data packet to verify loop
            behavior_payload = {
                "type": "behavioral_data",
                "userId": "kamalesh",
                "sessionId": "test-session",
                "keystrokeData": [],
                "mouseData": [{"x": i, "y": i, "t": i} for i in range(50)], # High activity
                "eyeData": []
            }
            await websocket.send(json.dumps(behavior_payload))
            print("Sent high-activity behavioral data payload.")
            
            # Listen for up to 3 responses (AnalysisResult, then potentially SessionTerminated)
            for _ in range(3):
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    resp_data = json.loads(response)
                    print(f"Received response type: {resp_data.get('type')} (Risk: {resp_data.get('riskScore')})")
                except asyncio.TimeoutError:
                    break
                except websockets.exceptions.ConnectionClosed:
                    print("Connection closed by server.")
                    break
            
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_handshake())
