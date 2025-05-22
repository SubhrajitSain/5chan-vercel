import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
import dotenv
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
from flask_socketio import SocketIO, emit, join_room, leave_room
from supabase import create_client, Client

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a_super_secret_key_that_should_be_in_env")

socketio = SocketIO(app, cors_allowed_origins="*")

MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable not set.")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))

db = client.get_database("5chan_db")
users_collection = db.users
boards_collection = db.boards
posts_collection = db.posts
comments_collection = db.comments

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")
SUPABASE_BUCKET_NAME = "5chanimages"

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_ANON_KEY environment variables not set.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
print(f"Supabase Client initialized for URL: {SUPABASE_URL}")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    boards = list(boards_collection.find().sort("created_at", -1))
    for board in boards:
        creator_user = users_collection.find_one({"_id": ObjectId(board['created_by'])})
        board['creator_username'] = creator_user['username'] if creator_user else "Anonymous"
    return render_template('index.html', boards=boards)

@app.route('/board/<board_name>')
def board(board_name):
    board_obj = boards_collection.find_one({"name": board_name})
    if not board_obj:
        flash(f"Board '/{board_name}/' does not exist.", "error")
        return redirect(url_for('index'))

    posts = list(posts_collection.find({"board_id": board_name}).sort("created_at", -1))
    for post in posts:
        creator_user = users_collection.find_one({"_id": ObjectId(post['user_id'])})
        post['author_username'] = creator_user['username'] if creator_user else "Anonymous"
        post['is_nsfw'] = post.get('is_nsfw', False)

    return render_template('board.html', board_name=board_name, posts=posts, board_obj=board_obj)

@app.route('/post/<post_id>')
def view_post(post_id):
    try:
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
    except Exception:
        flash("Invalid post ID.", "error")
        return redirect(url_for('index'))

    if not post:
        flash("Post not found.", "error")
        return redirect(url_for('index'))

    creator_user = users_collection.find_one({"_id": ObjectId(post['user_id'])})
    post['author_username'] = creator_user['username'] if creator_user else "Anonymous"
    post['is_nsfw'] = post.get('is_nsfw', False)

    comments = list(comments_collection.find({"post_id": ObjectId(post_id)}).sort("created_at", 1))
    for comment in comments:
        commenter_user = users_collection.find_one({"_id": ObjectId(comment['user_id'])})
        comment['commenter_username'] = commenter_user['username'] if commenter_user else "Anonymous"

    return render_template('post.html', post=post, comments=comments)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/tos')
def tos():
    return render_template('tos.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        if not (username and email and password):
            flash("All fields are required.", "error")
            return render_template('register.html')
        existing_user_email = users_collection.find_one({"email": email})
        if existing_user_email:
            flash("Email already registered. Please login or use a different email.", "error")
            return render_template('register.html')
        existing_user_username = users_collection.find_one({"username": username})
        if existing_user_username:
            flash("Username already taken. Please choose a different username.", "error")
            return render_template('register.html')
        try:
            password_hash = generate_password_hash(password)
            new_user_data = {
                "email": email,
                "username": username,
                "password_hash": password_hash,
                "created_at": datetime.utcnow()
            }
            result = users_collection.insert_one(new_user_data)
            user_id = str(result.inserted_id)
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An unexpected error occurred during registration: {e}", "error")
            print(f"Unexpected Exception during registration: {e}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Login failed: Incorrect email or password.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/create_board', methods=['GET', 'POST'])
def create_board():
    if 'user_id' not in session:
        flash("You must be logged in to create a board.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        board_name = request.form['name'].strip().lower()
        board_description = request.form['description'].strip()
        if not board_name:
            flash("Board name cannot be empty.", "error")
            return render_template('create_board.html')
        if not board_name.isalnum():
            flash("Board name must be alphanumeric (no spaces or special characters).", "error")
            return render_template('create_board.html')
        existing_board = boards_collection.find_one({"name": board_name})
        if existing_board:
            flash(f"Board name '/{board_name}/' already exists. Please choose a different name.", "error")
            return render_template('create_board.html')
        try:
            new_board_data = {
                "name": board_name,
                "description": board_description,
                "created_at": datetime.utcnow(),
                "created_by": session['user_id']
            }
            boards_collection.insert_one(new_board_data)
            flash(f"Board '/{board_name}/' created successfully!", "success")
            return redirect(url_for('board', board_name=board_name))
        except Exception as e:
            flash(f"An unexpected error occurred during board creation: {e}", "error")
            print(f"Unexpected Exception during board creation: {e}")
    return render_template('create_board.html')

@app.route('/create_post/<board_name>', methods=['GET', 'POST'])
def create_post(board_name):
    if 'user_id' not in session:
        flash("You must be logged in to create a post.", "warning")
        return redirect(url_for('login'))
    board_obj = boards_collection.find_one({"name": board_name})
    if not board_obj:
        flash(f"Board '/{board_name}/' does not exist. Cannot create post.", "error")
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        image_url = None
        is_nsfw = 'is_nsfw' in request.form

        if not content:
            flash("Post content cannot be empty.", "error")
            return render_template('create_post.html', board_name=board_name)
        if len(content) > 75:
            flash("Post content cannot exceed 75 characters.", "error")
            return render_template('create_post.html', board_name=board_name)

        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    file_content = file.read()

                    if not file_content:
                        flash("Uploaded file is empty.", "error")
                        return render_template('create_post.html', board_name=board_name)

                    print(f"Uploading file: {unique_filename}, MIME Type: {file.mimetype}, Size: {len(file_content)} bytes")

                    try:
                        bucket_path = f"public/{unique_filename}"
                        res = supabase.storage.from_(SUPABASE_BUCKET_NAME).upload(
                            bucket_path,
                            file_content,
                            {"content-type": file.mimetype}
                        )

                        if res.status_code == 200:
                            print(f"Image uploaded to Supabase Storage: {bucket_path}")
                            image_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET_NAME}/{bucket_path}"
                            print(f"Image Public URL: {image_url}")
                        else:
                            flash(f"Error uploading image to Supabase: {res.json().get('error', 'Unknown error')}", "error")
                            print(f"Supabase upload failed with status {res.status_code}: {res.text}")
                            return render_template('create_post.html', board_name=board_name)

                    except Exception as e:
                        flash(f"Error processing or uploading image: {e}", "error")
                        print(f"Exception during Supabase upload: {e}")
                        return render_template('create_post.html', board_name=board_name)
                else:
                    flash("Invalid file type.", "error")
                    return render_template('create_post.html', board_name=board_name)

        try:
            new_post_data = {
                "board_id": board_name,
                "user_id": session['user_id'],
                "username": session['username'],
                "title": title,
                "content": content,
                "image_url": image_url,
                "created_at": datetime.utcnow(),
                "is_nsfw": is_nsfw
            }
            posts_collection.insert_one(new_post_data)
            flash("Post created successfully!", "success")
            return redirect(url_for('board', board_name=board_name))
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
            print(f"Unexpected Exception during post creation: {e}")
    return render_template('create_post.html', board_name=board_name)

@app.route('/comment_on_post/<post_id>', methods=['POST'])
def comment_on_post(post_id):
    if 'user_id' not in session:
        flash("You must be logged in to comment.", "warning")
        return redirect(url_for('login'))
    content = request.form['content'].strip()

    if not content:
        flash("Comment content cannot be empty.", "error")
        return redirect(url_for('view_post', post_id=post_id))
    if len(content) > 75:
        flash("Comment content cannot exceed 75 characters.", "error")
        return redirect(url_for('view_post', post_id=post_id))

    try:
        post_obj = posts_collection.find_one({"_id": ObjectId(post_id)})
    except Exception:
        flash("Invalid post ID.", "error")
        return redirect(url_for('index'))
    if not post_obj:
        flash("Post not found.", "error")
        return redirect(url_for('index'))
    try:
        new_comment_data = {
            "post_id": ObjectId(post_id),
            "user_id": session['user_id'],
            "username": session['username'],
            "content": content,
            "created_at": datetime.utcnow()
        }
        comments_collection.insert_one(new_comment_data)
        flash("Comment added successfully!", "success")
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "error")
        print(f"Unexpected Exception during comment creation: {e}")
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/chat')
def chat():
    return render_template('chat.html', username=session.get('username'))

@socketio.on('connect')
def handle_connect():
    username = session.get('username', 'Anonymous')
    print(f'Client connected: {request.sid} (User: {username})')

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username', 'Anonymous')
    print(f'Client disconnected: {request.sid} (User: {username})')

@socketio.on('send_message')
def handle_message(data):
    message_content = data['message']
    username = session.get('username')

    if not username:
        emit('receive_message', {'msg': 'Please log in to send messages.', 'username': 'System', 'error': True})
        return

    timestamp = datetime.now().strftime('%H:%M:%S')
    emit('receive_message', {'username': username, 'message': message_content, 'timestamp': timestamp}, broadcast=True)
    print(f"[{timestamp}] {username}: {message_content}")

#if __name__ == '__main__':
#    socketio.run(app, debug=True, port=8080, allow_unsafe_werkzeug=True)
