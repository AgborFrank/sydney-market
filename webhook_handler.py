#!/usr/bin/env python3
"""
GitHub Webhook Handler for Auto-Deployment
This Flask application receives webhooks from GitHub and triggers deployment
"""

import os
import hmac
import hashlib
import subprocess
import logging
from flask import Flask, request, jsonify
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/webhook.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', 'your-webhook-secret-here')
DEPLOY_SCRIPT = '/var/www/marketplace/deploy.sh'
ALLOWED_BRANCHES = ['main', 'master']
DEPLOY_USER = 'www-data'  # User that should run the deployment

def verify_signature(payload_body, signature):
    """Verify GitHub webhook signature"""
    if not signature:
        return False
    
    # Remove 'sha256=' prefix
    if signature.startswith('sha256='):
        signature = signature[7:]
    
    # Calculate expected signature
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

def should_deploy(payload):
    """Determine if deployment should proceed based on webhook payload"""
    try:
        # Check if it's a push event
        if payload.get('ref_type') != 'tag' and 'refs/heads/' in payload.get('ref', ''):
            branch = payload['ref'].replace('refs/heads/', '')
            
            # Only deploy for allowed branches
            if branch in ALLOWED_BRANCHES:
                logger.info(f"Push detected on branch: {branch}")
                return True, branch
        
        # Check for tag pushes (optional)
        elif payload.get('ref_type') == 'tag':
            tag = payload.get('ref')
            logger.info(f"Tag push detected: {tag}")
            return True, tag
            
    except Exception as e:
        logger.error(f"Error parsing webhook payload: {e}")
    
    return False, None

def run_deployment():
    """Execute the deployment script"""
    try:
        logger.info("Starting deployment process...")
        
        # Run deployment script as the specified user
        result = subprocess.run(
            ['sudo', '-u', DEPLOY_USER, DEPLOY_SCRIPT],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            logger.info("Deployment completed successfully")
            return True, result.stdout
        else:
            logger.error(f"Deployment failed: {result.stderr}")
            return False, result.stderr
            
    except subprocess.TimeoutExpired:
        error_msg = "Deployment timed out after 5 minutes"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Deployment error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle GitHub webhook requests"""
    try:
        # Get the raw payload
        payload_body = request.get_data()
        
        # Verify signature
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_signature(payload_body, signature):
            logger.warning("Invalid webhook signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse JSON payload
        payload = request.get_json()
        if not payload:
            return jsonify({'error': 'Invalid JSON payload'}), 400
        
        # Log webhook event
        event_type = request.headers.get('X-GitHub-Event')
        logger.info(f"Received {event_type} webhook")
        
        # Check if we should deploy
        should_deploy_flag, branch_or_tag = should_deploy(payload)
        
        if should_deploy_flag:
            logger.info(f"Triggering deployment for {branch_or_tag}")
            
            # Run deployment
            success, output = run_deployment()
            
            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Deployment triggered successfully',
                    'branch': branch_or_tag,
                    'timestamp': datetime.utcnow().isoformat()
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Deployment failed',
                    'error': output,
                    'timestamp': datetime.utcnow().isoformat()
                }), 500
        else:
            logger.info("No deployment needed for this webhook")
            return jsonify({
                'status': 'skipped',
                'message': 'No deployment needed',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
    except Exception as e:
        logger.error(f"Webhook handler error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'webhook-handler',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/deploy', methods=['POST'])
def manual_deploy():
    """Manual deployment trigger (for testing)"""
    try:
        # Verify API key or token for manual deployments
        api_key = request.headers.get('X-API-Key')
        if api_key != os.environ.get('MANUAL_DEPLOY_KEY', 'your-manual-deploy-key'):
            return jsonify({'error': 'Invalid API key'}), 401
        
        logger.info("Manual deployment triggered")
        success, output = run_deployment()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Manual deployment completed',
                'output': output,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Manual deployment failed',
                'error': output,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
            
    except Exception as e:
        logger.error(f"Manual deployment error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Run in production with proper WSGI server
    app.run(host='0.0.0.0', port=5001, debug=False) 