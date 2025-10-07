from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)

def format_last_seen(last_login_datetime):
    """
    Format the last login time to show relative time or 'online' status.
    
    Args:
        last_login_datetime: datetime object of the last login time
        
    Returns:
        str: Formatted time string (e.g., "online", "1 hour ago", "2 days ago")
    """
    if not last_login_datetime:
        return "Never"
    
    try:
        # Get current time in the same timezone as last_login
        now = datetime.now(timezone.utc)
        if last_login_datetime.tzinfo is None:
            # If no timezone info, assume UTC
            last_login_datetime = last_login_datetime.replace(tzinfo=timezone.utc)
        
        # Calculate time difference
        time_diff = now - last_login_datetime
        
        # If last login was within the last 5 minutes, consider them online
        if time_diff <= timedelta(minutes=5):
            return "online"
        
        # If last login was within the last hour
        elif time_diff < timedelta(hours=1):
            minutes = int(time_diff.total_seconds() / 60)
            if minutes == 0:
                return "just now"
            elif minutes == 1:
                return "1 minute ago"
            else:
                return f"{minutes} minutes ago"
        
        # If last login was within the last 24 hours
        elif time_diff < timedelta(days=1):
            hours = int(time_diff.total_seconds() / 3600)
            if hours == 1:
                return "1 hour ago"
            else:
                return f"{hours} hours ago"
        
        # If last login was within the last week
        elif time_diff < timedelta(days=7):
            days = int(time_diff.total_seconds() / 86400)
            if days == 1:
                return "1 day ago"
            else:
                return f"{days} days ago"
        
        # If last login was within the last month
        elif time_diff < timedelta(days=30):
            days = int(time_diff.total_seconds() / 86400)
            weeks = days // 7
            if weeks == 1:
                return "1 week ago"
            else:
                return f"{weeks} weeks ago"
        
        # If last login was within the last year
        elif time_diff < timedelta(days=365):
            days = int(time_diff.total_seconds() / 86400)
            months = days // 30
            if months == 1:
                return "1 month ago"
            else:
                return f"{months} months ago"
        
        # If last login was more than a year ago
        else:
            days = int(time_diff.total_seconds() / 86400)
            years = days // 365
            if years == 1:
                return "1 year ago"
            else:
                return f"{years} years ago"
                
    except Exception as e:
        logger.error(f"Error formatting last seen time: {e}")
        # Fallback to original format if there's an error
        try:
            return last_login_datetime.strftime('%b %d, %Y')
        except:
            return "Unknown"

def is_online(last_login_datetime):
    """
    Check if a user is currently online (last login within 5 minutes).
    
    Args:
        last_login_datetime: datetime object of the last login time
        
    Returns:
        bool: True if user is considered online, False otherwise
    """
    if not last_login_datetime:
        return False
    
    try:
        now = datetime.now(timezone.utc)
        if last_login_datetime.tzinfo is None:
            last_login_datetime = last_login_datetime.replace(tzinfo=timezone.utc)
        
        time_diff = now - last_login_datetime
        return time_diff <= timedelta(minutes=5)
    except Exception as e:
        logger.error(f"Error checking online status: {e}")
        return False
