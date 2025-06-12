from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.database import get_db_connection
#from utils.security import validate_csrf_token
import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

forum_bp = Blueprint('forum', __name__)

def require_login(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access the forum.", 'error')
            return redirect(url_for('user.login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@forum_bp.route('/')
def index():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, title, description, created_at, (SELECT pusername FROM users WHERE id = created_by) as creator FROM forum_categories ORDER BY created_at DESC")
        categories = [dict(row) for row in c.fetchall()]
        
        for category in categories:
            c.execute("""
                SELECT COUNT(*) 
                FROM forum_threads 
                WHERE category_id = ?
            """, (category['id'],))
            category['thread_count'] = c.fetchone()[0]
            
            c.execute("""
                SELECT COUNT(*) 
                FROM forum_posts p
                JOIN forum_threads t ON p.thread_id = t.id
                WHERE t.category_id = ?
            """, (category['id'],))
            category['post_count'] = c.fetchone()[0]

    return render_template('forum/index.html', categories=categories, title="Forum")

@forum_bp.route('/category/<int:category_id>')
def category(category_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT title, description FROM forum_categories WHERE id = ?", (category_id,))
        category = c.fetchone()
        if not category:
            flash("Category not found.", 'error')
            return redirect(url_for('forum.index'))
        
        c.execute("""
            SELECT t.id, t.title, t.created_at, t.views, t.sticky, t.locked, 
                   (SELECT pusername FROM users WHERE id = t.created_by) as creator,
                   (SELECT COUNT(*) FROM forum_posts WHERE thread_id = t.id) as post_count
            FROM forum_threads t
            WHERE t.category_id = ?
            ORDER BY t.sticky DESC, t.created_at DESC
        """, (category_id,))
        threads = [dict(row) for row in c.fetchall()]

    return render_template('forum/category.html', category=dict(category), threads=threads, title=f"Forum - {category['title']}")

@forum_bp.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
@require_login
def thread(thread_id):
    if request.method == 'POST':
        validate_csrf_token()
        content = request.form.get('content', '').strip()
        if not content:
            flash("Post content cannot be empty.", 'error')
        else:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT locked FROM forum_threads WHERE id = ?", (thread_id,))
                locked = c.fetchone()['locked']
                if locked:
                    flash("This thread is locked.", 'error')
                else:
                    c.execute("INSERT INTO forum_posts (thread_id, content, created_by) VALUES (?, ?, ?)", 
                              (thread_id, content, session['user_id']))
                    conn.commit()
                    flash("Post added successfully!", 'success')

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE forum_threads SET views = views + 1 WHERE id = ?", (thread_id,))
        conn.commit()
        
        c.execute("""
            SELECT t.title, t.created_at, t.locked, (SELECT pusername FROM users WHERE id = t.created_by) as creator
            FROM forum_threads t
            WHERE t.id = ?
        """, (thread_id,))
        thread_data = c.fetchone()
        if not thread_data:
            flash("Thread not found.", 'error')
            return redirect(url_for('forum.index'))
        
        c.execute("""
            SELECT p.id, p.content, p.created_at, p.edited_at, (SELECT pusername FROM users WHERE id = p.created_by) as creator
            FROM forum_posts p
            WHERE p.thread_id = ?
            ORDER BY p.created_at ASC
        """, (thread_id,))
        posts = [dict(row) for row in c.fetchall()]

    return render_template('forum/thread.html', thread=dict(thread_data), posts=posts, title=f"Forum - {thread_data['title']}")

@forum_bp.route('/new_category', methods=['GET', 'POST'])
@require_login
def new_category():
    if request.method == 'POST':
        validate_csrf_token()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        
        if not title:
            flash("Category title is required.", 'error')
        else:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO forum_categories (title, description, created_by) VALUES (?, ?, ?)", 
                          (title, description, session['user_id']))
                conn.commit()
                flash("Category created successfully!", 'success')
                return redirect(url_for('forum.index'))
    
    return render_template('forum/new_category.html', title="New Forum Category")

@forum_bp.route('/new_thread/<int:category_id>', methods=['GET', 'POST'])
@require_login
def new_thread(category_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT title FROM forum_categories WHERE id = ?", (category_id,))
        category = c.fetchone()
        if not category:
            flash("Category not found.", 'error')
            return redirect(url_for('forum.index'))
    
    if request.method == 'POST':
        validate_csrf_token()
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash("Thread title and initial post content are required.", 'error')
        else:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO forum_threads (category_id, title, created_by) VALUES (?, ?, ?)", 
                          (category_id, title, session['user_id']))
                thread_id = c.lastrowid
                c.execute("INSERT INTO forum_posts (thread_id, content, created_by) VALUES (?, ?, ?)", 
                          (thread_id, content, session['user_id']))
                conn.commit()
                flash("Thread created successfully!", 'success')
                return redirect(url_for('forum.thread', thread_id=thread_id))
    
    return render_template('forum/new_thread.html', category_id=category_id, category_title=category['title'], title="New Thread")