from utils.database import get_db_connection

def has_active_subscription(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM vendor_subscriptions 
            WHERE vendor_id = ? AND status = 'active'
        """, (user_id,))
        return c.fetchone() is not None