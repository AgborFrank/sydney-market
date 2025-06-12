from utils.database import get_db_connection
import logging

logger = logging.getLogger(__name__)

def get_categories_with_counts():
    """
    Fetch all categories with product counts, organized hierarchically.
    Parent categories include product counts from all descendants.
    
    Returns:
        list: List of parent categories, each with a 'children' list.
    """
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch categories with direct product counts
            c.execute("""
                SELECT c.id, c.name, c.parent_id, COUNT(p.id) as product_count
                FROM categories c
                LEFT JOIN products p ON c.id = p.category_id
                GROUP BY c.id
                ORDER BY c.name
            """)
            categories = [dict(row) for row in c.fetchall()]
            logger.info(f"Fetched categories: {categories}")
            
            if not categories:
                logger.warning("No categories found in database.")
                return []
            
            # Initialize 'children' for all categories
            for cat in categories:
                cat['children'] = []
            logger.debug(f"Initialized children for categories: {len(categories)}")
            
            # Build hierarchical structure
            parent_cats = []
            cat_map = {cat['id']: cat for cat in categories}
            
            for cat in categories:
                logger.debug(f"Processing category: {cat['name']} (ID: {cat['id']})")
                if cat['parent_id'] is None:
                    parent_cats.append(cat)
                else:
                    if cat['parent_id'] not in cat_map:
                        logger.warning(f"Invalid parent_id {cat['parent_id']} for category {cat['name']} (ID: {cat['id']})")
                        continue
                    parent = cat_map[cat['parent_id']]
                    parent['children'].append(cat)
            
            # Aggregate product counts for parents
            def aggregate_product_counts(category):
                total = category['product_count']
                for child in category['children']:
                    total += aggregate_product_counts(child)
                category['product_count'] = total
                return total
            
            for parent in parent_cats:
                aggregate_product_counts(parent)
            
            logger.info(f"Parent categories with aggregated counts: {parent_cats}")
            return parent_cats
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}", exc_info=True)
        return []