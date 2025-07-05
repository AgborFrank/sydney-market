#!/usr/bin/env python3

from app import app
from flask import session

# Simulate admin session
with app.test_client() as client:
    with app.app_context():
        # Test without admin session (should redirect to login)
        response = client.get('/admin/faqs')
        print(f"FAQ route without admin session: {response.status_code}")
        print(f"Redirect location: {response.location if response.location else 'None'}")
        
        # Test with admin session
        with client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['role'] = 'admin'
        
        response = client.get('/admin/faqs')
        print(f"FAQ route with admin session: {response.status_code}")
        print(f"Response length: {len(response.data) if response.data else 0}")
        
        if response.status_code == 200:
            print("✅ FAQ route is working!")
        else:
            print("❌ FAQ route is not working properly") 