from utils.database import get_db_connection
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def get_latest_news(limit=10):
    """
    Fetch the latest news articles from the database.
    
    Args:
        limit (int): Maximum number of articles to return (default: 10).
    
    Returns:
        list: List of dictionaries containing news articles.
    """
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT n.id, n.title, n.content, n.created_at, u.pusername as admin_name
                FROM news n
                JOIN users u ON n.admin_id = u.id
                ORDER BY n.created_at DESC
                LIMIT ?
            """, (limit,))
            news_articles = [dict(row) for row in c.fetchall()]
            
            # Format created_at as "Month DD, YYYY"
            for article in news_articles:
                try:
                    article['created_at_formatted'] = datetime.strptime(
                        article['created_at'], '%Y-%m-%d %H:%M:%S'
                    ).strftime('%B %d, %Y')
                except ValueError:
                    article['created_at_formatted'] = article['created_at']
            
            return news_articles
    except Exception as e:
        logger.error(f"Error fetching news: {str(e)}")
        return []