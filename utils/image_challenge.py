"""
Image Challenge Security Module
Provides various image-based challenges for enhanced security
"""

import random
import string
import io
import logging
from PIL import Image, ImageDraw, ImageFont
import requests
from flask import session, send_file, make_response, current_app
import time
import os
import base64
from typing import List, Tuple, Dict, Any

# Challenge types
CHALLENGE_TYPES = [
    'click_specific_color',
    'click_shape',
    'drag_puzzle',
    'select_different',
    'count_objects',
    'find_pattern'
]

class ImageChallengeGenerator:
    """Generate various types of image challenges"""
    
    def __init__(self):
        self.challenge_data = {}
        self.session_key = 'image_challenge_data'
        
    def generate_challenge(self, challenge_type: str = None) -> Dict[str, Any]:
        """Generate a random image challenge"""
        if not challenge_type:
            challenge_type = random.choice(CHALLENGE_TYPES)
            
        challenge_id = self._generate_challenge_id()
        
        if challenge_type == 'click_specific_color':
            return self._generate_color_click_challenge(challenge_id)
        elif challenge_type == 'click_shape':
            return self._generate_shape_click_challenge(challenge_id)
        elif challenge_type == 'drag_puzzle':
            return self._generate_puzzle_challenge(challenge_id)
        elif challenge_type == 'select_different':
            return self._generate_difference_challenge(challenge_id)
        elif challenge_type == 'count_objects':
            return self._generate_count_challenge(challenge_id)
        elif challenge_type == 'find_pattern':
            return self._generate_pattern_challenge(challenge_id)
        else:
            return self._generate_color_click_challenge(challenge_id)
    
    def _generate_challenge_id(self) -> str:
        """Generate unique challenge ID"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    def _generate_color_click_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate click-specific-color challenge"""
        # Create image with multiple colored areas
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        # Define colors (one target, others distractor)
        colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6']
        target_color = random.choice(colors)
        colors.remove(target_color)
        
        # Draw colored rectangles
        rect_size = 60
        positions = []
        for i in range(6):
            row = i // 3
            col = i % 3
            x1 = col * 100 + 20
            y1 = row * 90 + 20
            x2 = x1 + rect_size
            y2 = y1 + rect_size
            
            color = target_color if i == 2 else random.choice(colors)
            draw.rectangle([x1, y1, x2, y2], fill=color)
            positions.append((x1, y1, x2, y2, color))
        
        # Convert to base64
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'click_specific_color',
            'target_color': target_color,
            'image': img_base64,
            'instructions': f'Click on the {target_color} colored square',
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _generate_shape_click_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate click-specific-shape challenge"""
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        shapes = ['circle', 'square', 'triangle']
        target_shape = random.choice(shapes)
        colors = ['#ef4444', '#22c55e', '#3b82f6']
        
        # Draw shapes
        for i in range(3):
            color = colors[i]
            center_x = 100 + i * 80
            center_y = 100
            
            if shapes[i] == 'circle':
                draw.ellipse([center_x-25, center_y-25, center_x+25, center_y+25], fill=color)
            elif shapes[i] == 'square':
                draw.rectangle([center_x-25, center_y-25, center_x+25, center_y+25], fill=color)
            elif shapes[i] == 'triangle':
                points = [(center_x, center_y-25), (center_x-25, center_y+25), (center_x+25, center_y+25)]
                draw.polygon(points, fill=color)
        
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'click_shape',
            'target_shape': target_shape,
            'image': img_base64,
            'instructions': f'Click on the {target_shape}',
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _generate_puzzle_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate drag-and-drop puzzle challenge"""
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        # Create a simple 4-piece puzzle
        puzzle_pieces = []
        piece_size = 60
        
        # Draw puzzle grid
        for row in range(2):
            for col in range(2):
                x1 = col * piece_size + 50
                y1 = row * piece_size + 50
                x2 = x1 + piece_size
                y2 = y1 + piece_size
                
                # Create puzzle piece shape (simplified)
                draw.rectangle([x1, y1, x2, y2], outline='#ffffff', width=2)
                
                # Add piece number
                try:
                    font = ImageFont.load_default()
                except:
                    font = None
                
                piece_text = str(row * 2 + col + 1)
                text_bbox = draw.textbbox((0, 0), piece_text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]
                text_x = x1 + (piece_size - text_width) // 2
                text_y = y1 + (piece_size - text_height) // 2
                draw.text((text_x, text_y), piece_text, fill='#ffffff', font=font)
        
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'drag_puzzle',
            'image': img_base64,
            'instructions': 'Arrange the puzzle pieces in correct order (1, 2, 3, 4)',
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _generate_difference_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate find-the-difference challenge"""
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        # Draw two similar images with one difference
        # Left side
        draw.rectangle([20, 50, 140, 150], outline='#3b82f6', width=2)
        draw.ellipse([60, 80, 100, 120], fill='#22c55e')  # Circle
        
        # Right side (with difference)
        draw.rectangle([160, 50, 280, 150], outline='#3b82f6', width=2)
        draw.rectangle([190, 80, 230, 120], fill='#ef4444')  # Square instead of circle
        
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'select_different',
            'image': img_base64,
            'instructions': 'Click on the difference between the two images',
            'difference_area': (190, 80, 230, 120),  # Right side square
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _generate_count_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate count objects challenge"""
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        # Draw random number of circles
        num_circles = random.randint(3, 8)
        colors = ['#ef4444', '#22c55e', '#3b82f6', '#f97316', '#8b5cf6']
        
        for i in range(num_circles):
            x = random.randint(30, 270)
            y = random.randint(30, 170)
            color = random.choice(colors)
            draw.ellipse([x-10, y-10, x+10, y+10], fill=color)
        
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'count_objects',
            'image': img_base64,
            'instructions': f'How many circles do you see? (Answer: {num_circles})',
            'correct_answer': num_circles,
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _generate_pattern_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Generate find pattern challenge"""
        width, height = 300, 200
        image = Image.new('RGB', (width, height), color='#1f2937')
        draw = ImageDraw.Draw(image)
        
        # Create a pattern with one odd item
        pattern = ['circle', 'square', 'circle', 'square', 'triangle', 'square']  # triangle is odd
        colors = ['#ef4444', '#22c55e', '#3b82f6']
        
        for i, shape in enumerate(pattern):
            x = 50 + i * 40
            y = 100
            color = colors[i % len(colors)]
            
            if shape == 'circle':
                draw.ellipse([x-15, y-15, x+15, y+15], fill=color)
            elif shape == 'square':
                draw.rectangle([x-15, y-15, x+15, y+15], fill=color)
            elif shape == 'triangle':
                points = [(x, y-15), (x-15, y+15), (x+15, y+15)]
                draw.polygon(points, fill=color)
        
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        challenge_data = {
            'id': challenge_id,
            'type': 'find_pattern',
            'image': img_base64,
            'instructions': 'Click on the shape that breaks the pattern',
            'odd_shape_index': 4,  # Index of triangle
            'created_at': time.time()
        }
        
        self._store_challenge_data(challenge_id, challenge_data)
        return challenge_data
    
    def _store_challenge_data(self, challenge_id: str, data: Dict[str, Any]):
        """Store challenge data in session"""
        try:
            if self.session_key not in session:
                session[self.session_key] = {}
            
            session[self.session_key][challenge_id] = data
            session.modified = True
        except Exception as e:
            logging.error(f"Failed to store challenge data: {e}")
    
    def get_challenge_data(self, challenge_id: str) -> Dict[str, Any]:
        """Retrieve challenge data from session"""
        try:
            if self.session_key not in session:
                return {}
            return session[self.session_key].get(challenge_id, {})
        except Exception as e:
            logging.error(f"Failed to get challenge data: {e}")
            return {}
    
    def validate_challenge_response(self, challenge_id: str, response: Dict[str, Any]) -> bool:
        """Validate user's response to challenge"""
        try:
            challenge_data = self.get_challenge_data(challenge_id)
            if not challenge_data:
                logging.warning(f"No challenge data found for ID: {challenge_id}")
                return False
            
            # Check if challenge expired (5 minutes)
            if time.time() - challenge_data.get('created_at', 0) > 300:
                logging.warning(f"Challenge expired for ID: {challenge_id}")
                self.clear_challenge(challenge_id)
                return False
            
            challenge_type = challenge_data.get('type')
            
            if challenge_type == 'click_specific_color':
                return response.get('color') == challenge_data.get('target_color')
            elif challenge_type == 'click_shape':
                return response.get('shape') == challenge_data.get('target_shape')
            elif challenge_type == 'drag_puzzle':
                # For simplicity, just check if user clicked submit
                return response.get('completed', False)
            elif challenge_type == 'select_different':
                # Check if user clicked in the difference area
                diff_area = challenge_data.get('difference_area', (0, 0, 0, 0))
                click_x = response.get('x', 0)
                click_y = response.get('y', 0)
                return (diff_area[0] <= click_x <= diff_area[2] and 
                       diff_area[1] <= click_y <= diff_area[3])
            elif challenge_type == 'count_objects':
                return response.get('count') == challenge_data.get('correct_answer')
            elif challenge_type == 'find_pattern':
                return response.get('selected_index') == challenge_data.get('odd_shape_index')
            
            return False
            
        except Exception as e:
            logging.error(f"Challenge validation error: {e}")
            return False
    
    def clear_challenge(self, challenge_id: str):
        """Clear challenge data from session"""
        try:
            if self.session_key in session and challenge_id in session[self.session_key]:
                del session[self.session_key][challenge_id]
                session.modified = True
        except Exception as e:
            logging.error(f"Failed to clear challenge: {e}")
    
    def clear_all_challenges(self):
        """Clear all challenge data from session"""
        try:
            session.pop(self.session_key, None)
            session.modified = True
        except Exception as e:
            logging.error(f"Failed to clear all challenges: {e}")


# Global instance
challenge_generator = ImageChallengeGenerator()


def generate_image_challenge(challenge_type: str = None) -> Dict[str, Any]:
    """Generate a new image challenge"""
    return challenge_generator.generate_challenge(challenge_type)


def validate_image_challenge_response(challenge_id: str, response: Dict[str, Any]) -> bool:
    """Validate user's response to image challenge"""
    return challenge_generator.validate_challenge_response(challenge_id, response)


def clear_image_challenge(challenge_id: str):
    """Clear specific challenge data"""
    challenge_generator.clear_challenge(challenge_id)


def is_image_challenge_required() -> bool:
    """Check if image challenge is required"""
    try:
        # Check if user has already completed challenge in this session
        return not session.get('image_challenge_verified', False)
    except Exception as e:
        logging.error(f"Error checking image challenge requirement: {e}")
        return True


def mark_image_challenge_verified():
    """Mark image challenge as completed"""
    try:
        session['image_challenge_verified'] = True
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to mark image challenge as verified: {e}")


def reset_image_challenge_verification():
    """Reset image challenge verification status"""
    try:
        session['image_challenge_verified'] = False
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to reset image challenge verification: {e}")
