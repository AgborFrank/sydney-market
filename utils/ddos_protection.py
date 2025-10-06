import redis
import time
import logging
import requests
from flask import request, abort, g
from config import Config
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading
import ipaddress

logger = logging.getLogger(__name__)

class DDoSProtection:
    """Comprehensive DDoS protection system with multiple layers of defense."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.config = Config()
        self.blocked_ips = set()
        self.whitelist_ips = set(self.config.DDOS_WHITELIST_IPS)
        self.lock = threading.Lock()
        
        # Initialize Redis keys with expiration
        self._init_redis_keys()
    
    def _init_redis_keys(self):
        """Initialize Redis keys with proper expiration times."""
        keys_to_init = {
            'ddos:blocked_ips': self.config.DDOS_BLOCK_DURATION,
            'ddos:burst_requests': self.config.DDOS_BURST_WINDOW,
            'ddos:minute_requests': 60,
            'ddos:hour_requests': 3600,
            'ddos:day_requests': 86400,
            'ddos:failed_logins': 300,  # 5 minutes
            'ddos:suspicious_activity': 1800,  # 30 minutes
        }
        
        for key, ttl in keys_to_init.items():
            if not self.redis.exists(key):
                self.redis.expire(key, ttl)
    
    def get_client_ip(self) -> str:
        """Get the real client IP address, handling proxies."""
        # Check for X-Forwarded-For header (common with proxies)
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            # Take the first IP in the chain
            return x_forwarded_for.split(',')[0].strip()
        
        # Check for X-Real-IP header
        x_real_ip = request.headers.get('X-Real-IP')
        if x_real_ip:
            return x_real_ip
        
        # Fallback to remote_addr
        return request.remote_addr
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        return ip in self.whitelist_ips
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        return self.redis.sismember('ddos:blocked_ips', ip)
    
    def block_ip(self, ip: str, reason: str = "DDoS protection"):
        """Block an IP address."""
        with self.lock:
            self.redis.sadd('ddos:blocked_ips', ip)
            self.redis.expire('ddos:blocked_ips', self.config.DDOS_BLOCK_DURATION)
            
            # Log the blocking
            block_data = {
                'ip': ip,
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat(),
                'user_agent': request.headers.get('User-Agent', ''),
                'path': request.path,
                'method': request.method
            }
            self.redis.lpush('ddos:block_log', json.dumps(block_data))
            self.redis.ltrim('ddos:block_log', 0, 999)  # Keep last 1000 blocks
            
            logger.warning(f"IP {ip} blocked: {reason}")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        with self.lock:
            self.redis.srem('ddos:blocked_ips', ip)
            logger.info(f"IP {ip} unblocked")
    
    def check_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        if not self.config.BLOCK_SUSPICIOUS_USER_AGENTS:
            return True
        
        user_agent_lower = user_agent.lower()
        for suspicious in self.config.SUSPICIOUS_USER_AGENTS:
            if suspicious in user_agent_lower:
                return False
        return True
    
    def check_ip_reputation(self, ip: str) -> bool:
        """Check IP reputation using external API."""
        if not self.config.ENABLE_IP_REPUTATION or not self.config.IP_REPUTATION_API_KEY:
            return True
        
        try:
            # Use a free IP reputation service (example with ipapi.co)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Check if IP is from a known hosting provider or VPN
                if data.get('isp', '').lower() in ['amazon', 'digitalocean', 'linode', 'vultr', 'ovh']:
                    return False
        except Exception as e:
            logger.error(f"IP reputation check failed for {ip}: {e}")
        
        return True
    
    def check_rate_limits(self, ip: str) -> Tuple[bool, str]:
        """Check various rate limits for an IP."""
        current_time = int(time.time())
        
        # Check burst limit (requests per short window)
        burst_key = f"ddos:burst:{ip}"
        burst_count = self.redis.get(burst_key)
        if burst_count and int(burst_count) > self.config.DDOS_BURST_LIMIT:
            return False, "Burst limit exceeded"
        
        # Check minute limit
        minute_key = f"ddos:minute:{ip}:{current_time // 60}"
        minute_count = self.redis.get(minute_key)
        if minute_count and int(minute_count) > self.config.DDOS_MAX_REQUESTS_PER_MINUTE:
            return False, "Minute limit exceeded"
        
        # Check hour limit
        hour_key = f"ddos:hour:{ip}:{current_time // 3600}"
        hour_count = self.redis.get(hour_key)
        if hour_count and int(hour_count) > self.config.DDOS_MAX_REQUESTS_PER_HOUR:
            return False, "Hour limit exceeded"
        
        # Check day limit
        day_key = f"ddos:day:{ip}:{current_time // 86400}"
        day_count = self.redis.get(day_key)
        if day_count and int(day_count) > self.config.DDOS_MAX_REQUESTS_PER_DAY:
            return False, "Day limit exceeded"
        
        return True, "OK"
    
    def increment_counters(self, ip: str):
        """Increment rate limit counters for an IP."""
        current_time = int(time.time())
        
        # Increment burst counter
        burst_key = f"ddos:burst:{ip}"
        self.redis.incr(burst_key)
        self.redis.expire(burst_key, self.config.DDOS_BURST_WINDOW)
        
        # Increment minute counter
        minute_key = f"ddos:minute:{ip}:{current_time // 60}"
        self.redis.incr(minute_key)
        self.redis.expire(minute_key, 60)
        
        # Increment hour counter
        hour_key = f"ddos:hour:{ip}:{current_time // 3600}"
        self.redis.incr(hour_key)
        self.redis.expire(hour_key, 3600)
        
        # Increment day counter
        day_key = f"ddos:day:{ip}:{current_time // 86400}"
        self.redis.incr(day_key)
        self.redis.expire(day_key, 86400)
    
    def check_request(self) -> Tuple[bool, str]:
        """Main method to check if a request should be allowed."""
        if not self.config.DDOS_ENABLED:
            return True, "DDoS protection disabled"
        
        client_ip = self.get_client_ip()
        
        # Check whitelist
        if self.is_ip_whitelisted(client_ip):
            return True, "IP whitelisted"
        
        # Check if IP is blocked
        if self.is_ip_blocked(client_ip):
            return False, "IP blocked"
        
        # Check user agent
        user_agent = request.headers.get('User-Agent', '')
        if not self.check_user_agent(user_agent):
            self.block_ip(client_ip, "Suspicious user agent")
            return False, "Suspicious user agent"
        
        # Check IP reputation
        if not self.check_ip_reputation(client_ip):
            self.block_ip(client_ip, "Low IP reputation")
            return False, "Low IP reputation"
        
        # Check rate limits
        allowed, reason = self.check_rate_limits(client_ip)
        if not allowed:
            self.block_ip(client_ip, reason)
            return False, reason
        
        # Increment counters for this request
        self.increment_counters(client_ip)
        
        return True, "OK"
    
    def get_statistics(self) -> Dict:
        """Get DDoS protection statistics."""
        stats = {
            'blocked_ips_count': self.redis.scard('ddos:blocked_ips'),
            'whitelisted_ips_count': len(self.whitelist_ips),
            'recent_blocks': [],
            'total_requests_today': 0,
            'blocked_requests_today': 0
        }
        
        # Get recent blocks
        recent_blocks = self.redis.lrange('ddos:block_log', 0, 9)
        for block in recent_blocks:
            try:
                stats['recent_blocks'].append(json.loads(block))
            except:
                pass
        
        return stats


class reCAPTCHA:
    """reCAPTCHA verification system."""
    
    def __init__(self):
        self.config = Config()
    
    def verify_recaptcha(self, recaptcha_response: str, remote_ip: str = None) -> bool:
        """Verify reCAPTCHA response."""
        if not self.config.RECAPTCHA_ENABLED:
            return True
        
        if not recaptcha_response:
            return False
        
        try:
            data = {
                'secret': self.config.RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            
            if remote_ip:
                data['remoteip'] = remote_ip
            
            response = requests.post(
                self.config.RECAPTCHA_VERIFY_URL,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('success', False)
            
        except Exception as e:
            logger.error(f"reCAPTCHA verification failed: {e}")
        
        return False
    
    def get_site_key(self) -> str:
        """Get reCAPTCHA site key for frontend."""
        return self.config.RECAPTCHA_SITE_KEY


# Global instances
ddos_protection = None
recaptcha = None

def init_ddos_protection(redis_client: redis.Redis):
    """Initialize DDoS protection system."""
    global ddos_protection, recaptcha
    ddos_protection = DDoSProtection(redis_client)
    recaptcha = reCAPTCHA()
    logger.info("DDoS protection and reCAPTCHA initialized")

def check_ddos_protection():
    """Decorator function to check DDoS protection on routes."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if ddos_protection:
                allowed, reason = ddos_protection.check_request()
                if not allowed:
                    logger.warning(f"Request blocked: {reason}")
                    abort(429, description=f"Rate limit exceeded: {reason}")
            return f(*args, **kwargs)
        return wrapper
    return decorator

def require_recaptcha():
    """Decorator to require reCAPTCHA verification."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if recaptcha and recaptcha.config.RECAPTCHA_ENABLED:
                recaptcha_response = request.form.get('g-recaptcha-response')
                if not recaptcha.verify_recaptcha(recaptcha_response, request.remote_addr):
                    abort(400, description="reCAPTCHA verification failed")
            return f(*args, **kwargs)
        return wrapper
    return decorator 