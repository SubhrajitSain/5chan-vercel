import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
import dotenv
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import cloudinary
import cloudinary.uploader

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a_super_secret_key_that_should_be_in_env")

MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable not set.")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))

db = client.get_database("5chan_db")
users_collection = db.users
boards_collection = db.boards
posts_collection = db.posts
comments_collection = db.comments
reports_collection = db.reports

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    raise RuntimeError(f"Error connecting to MongoDB: {e}")

CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

if not all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]):
    raise ValueError("Cloudinary environment variables not set.")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET,
    secure=True
)
print("Cloudinary Client initialized.")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

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

@app.route('/boards')
def boards():
    boards = list(boards_collection.find().sort("created_at", -1))
    for board in boards:
        creator_user = users_collection.find_one({"_id": ObjectId(board['created_by'])})
        board['creator_username'] = creator_user['username'] if creator_user else "Anonymous"
    return render_template('boards.html', boards=boards)

@app.route('/board/<board_name>')
def board(board_name):
    board_obj = boards_collection.find_one({"name": board_name})
    if not board_obj:
        flash(f"Board '/{board_name}/' does not exist or has been removed.", "error")
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
        comment['commenter_username'] = commenter_user['username'] if commenter_user else "N/A"

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
            flash("Email address already in use.", "error")
            return render_template('register.html')
        existing_user_username = users_collection.find_one({"username": username})
        if existing_user_username:
            flash("Username has already been taken.", "error")
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
            flash("You have been registered successfully. Use your email and password to login.", "success")
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
            flash(f"You are now logged in as {session['username']}.", "success")
            return redirect(url_for('index'))
        else:
            flash("Incorrect email or password.", "error")
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
        if len(board_description) > 100:
            flash("Description cannot be more than 100 characters long.", "error")
            return render_template('create_board.html')
        existing_board = boards_collection.find_one({"name": board_name})
        if existing_board:
            flash(f"Board name '/{board_name}/' already exists.", "error")
            return render_template('create_board.html')
        try:
            new_board_data = {
                "name": board_name,
                "description": board_description,
                "created_at": datetime.utcnow(),
                "created_by": session['user_id']
            }
            boards_collection.insert_one(new_board_data)
            flash(f"Board '/{board_name}/' created successfully.", "success")
            return redirect(url_for('board', board_name=board_name))
        except Exception as e:
            flash(f"An unexpected error occurred during board creation: {e}", "error")
            print(f"Unexpected Exception during board creation: {e}")
    return render_template('create_board.html')

@app.route('/settings', methods=['GET', 'POST'])
def profile_settings():
    if 'user_id' not in session:
        flash("You must be logged in to access your settings.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        flash("User not found.", "error")
        session.pop('user_id', None)
        session.pop('username', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form.get('username_new_username', '').strip()
        if new_username and new_username != user['username']:
            if users_collection.find_one({"username": new_username}):
                flash("Username already taken.", "error")
            else:
                try:
                    users_collection.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {"username": new_username}}
                    )
                    session['username'] = new_username
                    flash("Username updated successfully.", "success")
                    user['username'] = new_username
                except Exception as e:
                    flash(f"Error updating username: {e}", "error")

        new_email = request.form.get('email_new_email', '').strip()
        if new_email and new_email != user['email']:
            if users_collection.find_one({"email": new_email}):
                flash("Email already registered by another user.", "error")
            else:
                try:
                    users_collection.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {"email": new_email}}
                    )
                    flash("Email updated successfully.", "success")
                    user['email'] = new_email
                except Exception as e:
                    flash(f"Error updating email: {e}", "error")

        current_password = request.form.get('password_current_password')
        new_password = request.form.get('password_new_password')
        confirm_password = request.form.get('password_confirm_password')

        if new_password:
            if not current_password:
                flash("Current password is required to set a new password.", "error")
            elif not check_password_hash(user['password_hash'], current_password):
                flash("Incorrect current password.", "error")
            elif new_password != confirm_password:
                flash("New and confirmation passwords do not match.", "error")
            elif len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "error")
            else:
                try:
                    new_password_hash = generate_password_hash(new_password)
                    users_collection.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {"password_hash": new_password_hash}}
                    )
                    flash("Password updated successfully!", "success")
                except Exception as e:
                    flash(f"Error updating password: {e}", "error")
        return redirect(url_for('profile_settings'))
    return render_template('profile_settings.html', user=user)

@app.route('/create_post/<board_name>', methods=['GET', 'POST'])
def create_post(board_name):
    if 'user_id' not in session:
        flash("You must be logged in to create a post.", "warning")
        return redirect(url_for('login'))
    board_obj = boards_collection.find_one({"name": board_name})
    if not board_obj:
        flash(f"Board '/{board_name}/' does not exist.", "error")
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
                    public_id = f"5chan_images/{uuid.uuid4()}_{os.path.splitext(filename)[0]}"

                    file_content = file.read()
                    file.seek(0)

                    if not file_content:
                        flash("Uploaded file's content is empty.", "error")
                        return render_template('create_post.html', board_name=board_name)

                    if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
                        flash(f"File size exceeds the limit of {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.0f}MB.", "error")
                        return render_template('create_post.html', board_name=board_name)

                    print(f"Attempting upload to Cloudinary. Public ID: {public_id}, MIME Type: {file.mimetype}, Size: {len(file_content)} bytes")

                    try:
                        upload_result = cloudinary.uploader.upload(
                            file.stream,
                            public_id=public_id,
                            folder="5chan_images",
                            resource_type="image"
                        )

                        if upload_result and 'secure_url' in upload_result:
                            image_url = upload_result['secure_url']
                            print(f"Image uploaded to Cloudinary: {image_url}")
                        else:
                            flash(f"Error uploading image: {upload_result.get('error', 'Error cause N/A')}", "error")
                            print(f"Cloudinary upload failed: {upload_result}")
                            return render_template('create_post.html', board_name=board_name)

                    except Exception as e:
                        flash(f"Error processing or uploading image: {e}", "error")
                        print(f"Cloudinary upload exception: {e}")
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
            flash(f"Post created successfully in /{board_name}/.", "success")
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

@app.route('/report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        flash("You must be logged in to submit a report.", "warning")
        return redirect(url_for('login'))

    report_subjects = [
        "Spam",
        "Harassment / Hate Speech",
        "Illegal Content",
        "Unmarked NSFW / Inappropriate Content",
        "Impersonation",
        "Bug Report",
        "Feature Suggestion",
        "Other"
    ]

    if request.method == 'POST':
        reporter_username = session.get('username')
        reported_username = request.form.get('reported_username', '').strip()
        board_name = request.form.get('board_name', '').strip()
        post_id = request.form.get('post_id', '').strip()
        report_subject = request.form.get('report_subject', '').strip()
        other_subject = request.form.get('other_subject', '').strip()
        summary = request.form.get('summary', '').strip()

        if not reported_username:
            flash("An username s required. If you are reporting a bug or suggestion, please enter 'Bug' or 'Suggestion' instead.", "error")
            return render_template('report.html', report_subjects=report_subjects)
        if not report_subject:
            flash("Please select a report subject.", "error")
            return render_template('report.html', report_subjects=report_subjects)
        if report_subject == "Other" and not other_subject:
            flash("Please specify the 'Other' subject.", "error")
            return render_template('report.html', report_subjects=report_subjects)
        if not summary:
            flash("A summary of the report is required.", "error")
            return render_template('report.html', report_subjects=report_subjects)
        if len(summary) < 10 or len(summary) > 500:
            flash("Summary must be between 10 and 500 characters.", "error")
            return render_template('report.html', report_subjects=report_subjects)

        final_subject = other_subject if report_subject == "Other" else report_subject

        target_board = None
        target_post = None

        if board_name:
            target_board = boards_collection.find_one({"name": board_name})
            if not target_board:
                flash(f"Board '/{board_name}/' does not exist.", "error")
                return render_template('report.html', report_subjects=report_subjects)

        if post_id:
            try:
                target_post = posts_collection.find_one({"_id": ObjectId(post_id)})
            except Exception:
                flash("Invalid Post ID format.", "error")
                return render_template('report.html', report_subjects=report_subjects)
            if not target_post:
                flash("Post with the provided ID does not exist. Either you mistyped or the post has been already removed.", "error")
                return render_template('report.html', report_subjects=report_subjects)
            if target_board and target_post['board_id'] != target_board['name']:
                 flash("The provided Post ID does not belong to the specified board.", "error")
                 return render_template('report.html', report_subjects=report_subjects)

        try:
            report_data = {
                "reporter_id": session['user_id'],
                "reporter_username": reporter_username,
                "reported_username_reason": reported_username,
                "board_name": board_name if board_name else None,
                "post_id": ObjectId(post_id) if post_id else None,
                "subject": final_subject,
                "summary": summary,
                "status": "pending",
                "created_at": datetime.utcnow()
            }
            reports_collection.insert_one(report_data)
            flash("Your report has been submitted successfully.", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"An unexpected error occurred during report submission: {e}", "error")
            print(f"Error submitting report: {e}")

    return render_template('report.html', report_subjects=report_subjects)

@app.route('/api/board/<board_name>/edit_description', methods=['POST'])
def edit_board_description(board_name):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized: You must be logged in to edit board descriptions."}), 401

    board_obj = boards_collection.find_one({"name": board_name})
    if not board_obj:
        return jsonify({"error": f"Board '{board_name}' not found."}), 404

    if session['user_id'] != board_obj['created_by']:
        return jsonify({"error": "Forbidden: You are not the creator of this board."}), 403

    data = request.get_json()
    new_description = data.get('description', '').strip()

    if len(new_description) > 100:
        return jsonify({"error": "Description too long. Maximum 100 characters."}), 400

    try:
        boards_collection.update_one(
            {"_id": board_obj['_id']},
            {"$set": {"description": new_description}}
        )
        return jsonify({"message": "Board description updated successfully."}), 200
    except Exception as e:
        print(f"Error updating board description: {e}")
        return jsonify({"error": "Internal server error occurred while updating description."}), 500

@app.route('/api/post/<post_id>/edit_content', methods=['POST'])
def edit_post_content(post_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized: You must be logged in to edit posts."}), 401

    try:
        post_obj = posts_collection.find_one({"_id": ObjectId(post_id)})
    except Exception:
        return jsonify({"error": "Invalid post ID format."}), 400

    if not post_obj:
        return jsonify({"error": "Post not found."}), 404

    if session['user_id'] != post_obj['user_id']:
        return jsonify({"error": "Forbidden: You are not the creator of this post."}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data in request body."}), 400

    new_content = data.get('content', '').strip()

    if len(new_content) > 75:
        return jsonify({"error": "Post content too long. Maximum 75 characters."}), 400

    try:
        posts_collection.update_one(
            {"_id": post_obj['_id']},
            {"$set": {"content": new_content}}
        )
        return jsonify({"message": "Post content updated successfully."}), 200
    except Exception as e:
        print(f"Error updating post content: {e}")
        return jsonify({"error": "Internal server error occurred while updating post content."}), 500

@app.errorhandler(400)
def bad_request_error(e):
    return render_template('error.html', error_code=400, error_message="Bad Request: The server cannot process the request due to a client error (e.g., malformed syntax)."), 400

@app.errorhandler(401)
def unauthorized_error(e):
    return render_template('error.html', error_code=401, error_message="Unauthorized: Authentication is required or has failed. Please log in."), 401

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('error.html', error_code=403, error_message="Forbidden: You do not have permission to access this resource."), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Not Found: The page you are looking for does not exist."), 404

@app.errorhandler(405)
def method_not_allowed_error(e):
    return render_template('error.html', error_code=405, error_message="Method Not Allowed: The requested method is not supported for this URL."), 405

@app.errorhandler(408)
def request_timeout_error(e):
    return render_template('error.html', error_code=408, error_message="Request Timeout: The server timed out waiting for the request."), 408

@app.errorhandler(413) # Payload Too Large
def request_entity_too_large(e):
    return render_template('error.html', error_code=413, error_message=f"Payload Too Large: The file you uploaded is too large. Maximum allowed size is {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):.0f}MB."), 413

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal Server Error: Something went wrong on our end. We're working to fix it!"), 500

@app.errorhandler(502)
def bad_gateway_error(e):
    return render_template('error.html', error_code=502, error_message="Bad Gateway: The server received an invalid response from an upstream server."), 502

@app.errorhandler(503)
def service_unavailable_error(e):
    return render_template('error.html', error_code=503, error_message="Service Unavailable: The server is currently unable to handle the request due to temporary overloading or maintenance of the server."), 503

if __name__ == '__main__':
    app.run(debug=True, port=8080)
