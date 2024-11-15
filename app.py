import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime, timedelta

sqlite = "sqlite3 projects.db"

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database setup
def init_db():
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        # Create tables
        c.execute('''CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            profile_image TEXT,
            location TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS Resources (
            resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            images TEXT,
            category TEXT,
            availability TEXT,
            date_posted TEXT, 
            pickup_location TEXT,   
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS Messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT NOT NULL,
            timestamp TEXT,
            FOREIGN KEY (sender_id) REFERENCES Users(user_id),
            FOREIGN KEY (receiver_id) REFERENCES Users(user_id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS Reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            reviewer_id INTEGER,
            rating INTEGER,
            comment TEXT,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES Users(user_id),
            FOREIGN KEY (reviewer_id) REFERENCES Users(user_id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS Bookings (
            booking_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            resource_id INTEGER,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(user_id),
            FOREIGN KEY (resource_id) REFERENCES Resources(resource_id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS CommunityEvents (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            date TEXT NOT NULL,
            time TEXT,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        )''')

         # Add EventRSVPs table
        c.execute('''CREATE TABLE IF NOT EXISTS EventRSVPs (
            rsvp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (event_id) REFERENCES CommunityEvents(event_id),
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        )''')

        conn.commit()

# Initialize the database
init_db()

#Index Page
@app.route('/')
def index():
    return render_template('index.html')

#About Page
@app.route('/about')
def about():
    return render_template('about.html')

# Register User
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        location = request.form.get('location', '')

        # Password validation logic
        def validate_password(password):
            if len(password) < 8:
                return "Password must be at least 8 characters long."
            if not any(char.isupper() for char in password):
                return "Password must contain at least one uppercase letter."
            if not any(char.islower() for char in password):
                return "Password must contain at least one lowercase letter."
            if not any(char.isdigit() for char in password):
                return "Password must contain at least one number."
            if not any(char in "@$!%*?&" for char in password):  # Adjust allowed special characters as needed
                return "Password must contain at least one special character (@, $, !, %, *, ?, &)."
            return None

        # Validate the password
        password_error = validate_password(password)
        if password_error:
            error = password_error
        
        # Additional server-side validations
        elif not name or len(name) > 50:
            error = "Name is required and must be 50 characters or fewer."
        elif not email or "@" not in email or len(email) > 100:
            error = "A valid email address is required and must be 100 characters or fewer."
        
        # Check if email already exists
        if not error:
            with sqlite3.connect('projects.db') as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM Users WHERE email = ?", (email,))
                existing_user = c.fetchone()
                if existing_user:
                    error = "An account with this email already exists."

        if error:
            return render_template('register.html', error=error)

        # Profile image handling
        profile_image = request.files['profile_image']
        profile_image_filename = None
        if profile_image and profile_image.filename != '':
            if profile_image.content_length > 2 * 1024 * 1024:  # Limit file size to 2MB
                error = "Profile image must be under 2MB."
                return render_template('register.html', error=error)

            filename = secure_filename(profile_image.filename)
            profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image_filename = filename

        # Save to the database if no validation errors
        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO Users (name, email, password, profile_image, location)
                         VALUES (?, ?, ?, ?, ?)''', 
                      (name, email, generate_password_hash(password), profile_image_filename, location))
            conn.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM Users WHERE email = ?', (email,))
            user = c.fetchone()
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                
                # Print the user ID to the console
                print(f"Logged in user ID: {session['user_id']}")
                
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid email or password.'
    
    return render_template('login.html', error=error)

# User Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

#Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    unread_notifications = get_unread_notifications(user_id)  # Get the unread notifications count
    notifications = get_recent_notifications(user_id)  # Get recent notifications for the dropdown

    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Fetch the user's resources
        c.execute('SELECT * FROM Resources WHERE user_id = ?', (user_id,))
        resources = c.fetchall()

        # Fetch reviews about the user's resources
        c.execute('''
            SELECT Reviews.comment, Reviews.rating, Reviews.timestamp, Users.name AS reviewer_name, Resources.title AS resource_title
            FROM Reviews
            JOIN Resources ON Reviews.resource_id = Resources.resource_id
            JOIN Users ON Reviews.reviewer_id = Users.user_id
            WHERE Resources.user_id = ?
            ORDER BY Reviews.timestamp DESC
        ''', (user_id,))
        reviews = c.fetchall()

        # Fetch messages for the user
        c.execute('''SELECT Messages.content, Messages.timestamp, Users.name AS sender_name
                     FROM Messages
                     JOIN Users ON Messages.sender_id = Users.user_id
                     WHERE Messages.sender_id = ? OR Messages.receiver_id = ?
                     ORDER BY Messages.timestamp DESC''', (user_id, user_id))
        messages = c.fetchall()

        # Fetch resource reservations
        c.execute('''SELECT Bookings.booking_id, Bookings.start_date, Bookings.end_date, Resources.title, Resources.resource_id
                     FROM Bookings
                     JOIN Resources ON Bookings.resource_id = Resources.resource_id
                     WHERE Bookings.user_id = ?''', (user_id,))
        reservations = c.fetchall()

        # Fetch RSVP-ed events
        c.execute('''SELECT CommunityEvents.event_id, CommunityEvents.title, CommunityEvents.date, CommunityEvents.location
                     FROM EventRSVPs
                     JOIN CommunityEvents ON EventRSVPs.event_id = CommunityEvents.event_id
                     WHERE EventRSVPs.user_id = ?''', (user_id,))
        rsvps = c.fetchall()

        # Fetch conversations
        c.execute('''
            SELECT DISTINCT receiver_id, Users.name 
            FROM Messages 
            JOIN Users ON Messages.receiver_id = Users.user_id 
            WHERE sender_id = ? OR receiver_id = ?
        ''', (user_id, user_id))
        conversations = c.fetchall()

    return render_template(
        'dashboard.html', 
        resources=resources, reviews=reviews, messages=messages, reservations=reservations, rsvps=rsvps, conversations=conversations, unread_notifications=unread_notifications, notifications=notifications  
    )

def get_unread_notifications(user_id):
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Count unread messages
        c.execute('''SELECT COUNT(*) AS count FROM Messages 
                     WHERE receiver_id = ?''', (user_id,))
        unread_messages = c.fetchone()['count']

        # Count new bookings for user's resources
        c.execute('''SELECT COUNT(*) AS count FROM Bookings 
                     JOIN Resources ON Bookings.resource_id = Resources.resource_id 
                     WHERE Resources.user_id = ?''', (user_id,))
        new_bookings = c.fetchone()['count']

        # Count RSVPs for events created by the user
        c.execute('''SELECT COUNT(*) AS count FROM EventRSVPs 
                     JOIN CommunityEvents ON EventRSVPs.event_id = CommunityEvents.event_id 
                     WHERE CommunityEvents.user_id = ?''', (user_id,))
        new_rsvps = c.fetchone()['count']

    # Sum all notifications
    return unread_messages + new_bookings + new_rsvps

def get_recent_notifications(user_id):
    notifications = []
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Fetch recent messages
        c.execute('''
            SELECT 'New message from ' || Users.name AS message, Messages.timestamp 
            FROM Messages
            JOIN Users ON Messages.sender_id = Users.user_id
            WHERE Messages.receiver_id = ?
            ORDER BY Messages.timestamp DESC LIMIT 5
        ''', (user_id,))
        notifications += [{'message': row['message'], 'timestamp': row['timestamp']} for row in c.fetchall()]

        # Fetch recent bookings for user's resources
        c.execute('''
            SELECT 'New booking for ' || Resources.title AS message, Bookings.start_date AS timestamp 
            FROM Bookings
            JOIN Resources ON Bookings.resource_id = Resources.resource_id 
            WHERE Resources.user_id = ?
            ORDER BY Bookings.start_date DESC LIMIT 5
        ''', (user_id,))
        notifications += [{'message': row['message'], 'timestamp': row['timestamp']} for row in c.fetchall()]

        # Fetch recent RSVPs for events created by the user (avoid contraction in SQL)
        c.execute('''
            SELECT Users.name || ' RSVP to your event ' || CommunityEvents.title AS message, 
                   CommunityEvents.date || ' ' || COALESCE(CommunityEvents.time, '00:00:00') AS timestamp
            FROM EventRSVPs
            JOIN CommunityEvents ON EventRSVPs.event_id = CommunityEvents.event_id
            JOIN Users ON EventRSVPs.user_id = Users.user_id
            WHERE CommunityEvents.user_id = ?
            ORDER BY CommunityEvents.date DESC, CommunityEvents.time DESC LIMIT 5
        ''', (user_id,))
        notifications += [{'message': row['message'], 'timestamp': row['timestamp']} for row in c.fetchall()]

    # Sort notifications by timestamp in reverse order for recent notifications first
    notifications = sorted(notifications, key=lambda x: x['timestamp'], reverse=True)
    return notifications

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    # Fetch all relevant notifications for the user
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Unread messages
        c.execute('''SELECT Messages.content, Messages.timestamp, Users.name AS sender_name
                     FROM Messages
                     JOIN Users ON Messages.sender_id = Users.user_id
                     WHERE Messages.receiver_id = ?''', (user_id,))
        unread_messages = c.fetchall()
        
        # New bookings for user's resources
        c.execute('''SELECT Bookings.start_date, Bookings.end_date, Resources.title AS resource_title
                     FROM Bookings
                     JOIN Resources ON Bookings.resource_id = Resources.resource_id
                     WHERE Resources.user_id = ?''', (user_id,))
        new_bookings = c.fetchall()
        
        # RSVPs for events created by the user
        c.execute('''SELECT EventRSVPs.event_id, CommunityEvents.title AS event_title, Users.name AS rsvp_user
                     FROM EventRSVPs
                     JOIN CommunityEvents ON EventRSVPs.event_id = CommunityEvents.event_id
                     JOIN Users ON EventRSVPs.user_id = Users.user_id
                     WHERE CommunityEvents.user_id = ?''', (user_id,))
        new_rsvps = c.fetchall()

    # Pass notifications to the template
    return render_template('notifications.html', unread_messages=unread_messages, new_bookings=new_bookings, new_rsvps=new_rsvps)

# CRUD Operations for Resources

# Add Resource
@app.route('/resource/add', methods=['GET', 'POST'])
def add_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        availability = request.form['availability']
        date_posted = datetime.now().strftime('%Y-%m-%d')
        pickup_location = request.form['pickup_location']
        user_id = session['user_id']  # Ensure the current user's ID is used

        # Handle image upload
        images = request.files['images']
        image_filename = None
        if images and images.filename != '':
            image_filename = secure_filename(images.filename)
            images.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO Resources (user_id, title, description, images, category, availability, date_posted, pickup_location)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',  # Corrected to 8 placeholders
                      (user_id, title, description, image_filename, category, availability, date_posted, pickup_location))
            conn.commit()
        return redirect(url_for('resources'))
    
    return render_template('resource_form.html')

# Edit Resource
@app.route('/resource/edit/<int:resource_id>', methods=['GET', 'POST'])
def edit_resource(resource_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            category = request.form['category']
            availability = request.form['availability']
            pickup_location = request.form['pickup_location']

            # Handle image upload if new image is uploaded
            images = request.files['images']
            image_filename = None
            if images and images.filename != '':
                image_filename = secure_filename(images.filename)
                images.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

            # Update the resource in the database
            c.execute('''UPDATE Resources SET title=?, description=?, images=?, category=?, availability=?, pickup_location=?
                         WHERE resource_id=? AND user_id=?''', 
                      (title, description, image_filename, category, availability, pickup_location, resource_id, session['user_id']))
            conn.commit()
            return redirect(url_for('resource_details', resource_id=resource_id))

        # Fetch existing resource data to pre-fill form
        c.execute('SELECT * FROM Resources WHERE resource_id = ? AND user_id = ?', (resource_id, session['user_id']))
        resource = c.fetchone()
        if resource:
            return render_template('resource_form.html', resource=resource, editing=True)
        else:
            flash("Resource not found or access denied.")
            return redirect(url_for('dashboard'))
        
#Delete Resource
@app.route('/resource/delete/<int:resource_id>', methods=['POST'])
def delete_resource(resource_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM Resources WHERE resource_id = ? AND user_id = ?', (resource_id, session['user_id']))
        conn.commit()
    return redirect(url_for('dashboard'))

#Resource details
@app.route('/resource/<int:resource_id>', methods=['GET', 'POST'])
def resource_details(resource_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Fetch resource details
        c.execute('SELECT * FROM Resources WHERE resource_id = ?', (resource_id,))
        resource = c.fetchone()
        
        # Fetch owner details including owner user_id
        c.execute('SELECT user_id, name, profile_image FROM Users WHERE user_id = ?', (resource['user_id'],))
        owner = c.fetchone()
        owner_user_id = owner['user_id'] if owner else None  # Save owner user_id for messaging

        # Fetch reviews for this resource
        c.execute('''SELECT Reviews.comment, Reviews.rating, Reviews.timestamp, Users.name AS reviewer_name
                     FROM Reviews
                     JOIN Users ON Reviews.reviewer_id = Users.user_id
                     WHERE Reviews.resource_id = ?''', (resource_id,))
        reviews = c.fetchall()
        
        # Calculate the average rating for the resource owner (not just this resource)
        c.execute('SELECT rating FROM Reviews WHERE user_id = ?', (owner_user_id,))
        owner_ratings = [int(row['rating']) for row in c.fetchall()]
        average_rating = round(sum(owner_ratings) / len(owner_ratings), 1) if owner_ratings else 0

        # Fetch bookings for availability
        c.execute('SELECT start_date, end_date FROM Bookings WHERE resource_id = ?', (resource_id,))
        bookings = c.fetchall()

    # Generate list of unavailable dates
    unavailable_dates = []
    for booking in bookings:
        if booking['start_date'] and booking['end_date']:  
            start_date = datetime.strptime(booking['start_date'], '%Y-%m-%d')
            end_date = datetime.strptime(booking['end_date'], '%Y-%m-%d')
            current_date = start_date
            while current_date <= end_date:
                unavailable_dates.append(current_date.strftime('%Y-%m-%d'))
                current_date += timedelta(days=1)

    # Handle booking requests
    if request.method == 'POST' and 'start_date' in request.form and 'end_date' in request.form:
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Check if end date is before start date
        if end_date < start_date:
            flash("End date cannot be before the start date. Please select a valid date range.")
            return redirect(url_for('resource_details', resource_id=resource_id))

        # Check for overlapping bookings
        overlap = any(d >= start_date and d <= end_date for d in unavailable_dates)
        if overlap:
            flash("Selected dates are not available.")
            return redirect(url_for('resource_details', resource_id=resource_id))

        # Save booking and get the reservation ID
        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO Bookings (user_id, resource_id, start_date, end_date) VALUES (?, ?, ?, ?)',
                      (user_id, resource_id, start_date, end_date))
            conn.commit()
            reservation_id = c.lastrowid

        # Redirect to resource confirmation page with reservation ID
        return redirect(url_for('resource_confirmation', booking_id=reservation_id))

    return render_template(
        'resource_details.html', resource=resource, owner=owner, owner_user_id=owner_user_id, reviews=reviews, unavailable_dates=unavailable_dates, average_rating=average_rating
    )

# Resource Confirmation
@app.route('/resource_confirmation/<int:booking_id>')
def resource_confirmation(booking_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row  # Enable accessing columns by name
        c = conn.cursor()

        # Fetch reservation details
        c.execute('''SELECT start_date, end_date, resource_id, user_id
                     FROM Bookings WHERE booking_id = ?''', (booking_id,))
        reservation = c.fetchone()

        if not reservation:
            flash("Reservation not found.")
            return redirect(url_for('dashboard'))

        # Fetch resource details
        c.execute('SELECT title, description, pickup_location, user_id FROM Resources WHERE resource_id = ?', (reservation['resource_id'],))
        resource_data = c.fetchone()

        if resource_data:
            resource = {
                'title': resource_data['title'],
                'description': resource_data['description'],
                'pickup_location': resource_data['pickup_location']
            }
        else:
            flash("Error retrieving resource details.")
            return redirect(url_for('dashboard'))

        # Fetch owner details, including profile_image
        owner_user_id = resource_data['user_id']  # Fetching the user_id from the resource data
        c.execute('SELECT name, email, profile_image FROM Users WHERE user_id = ?', (owner_user_id,))
        owner_data = c.fetchone()
        
        if not owner_data:
            flash("Owner details not found.")
            return redirect(url_for('dashboard'))

        owner = {
            'name': owner_data['name'],
            'email': owner_data['email'],
            'profile_image': owner_data['profile_image']  # Include profile_image in the owner dictionary
        }

    # Calculate total days and total cost
    start_date = datetime.strptime(reservation['start_date'], '%Y-%m-%d')
    end_date = datetime.strptime(reservation['end_date'], '%Y-%m-%d')
    total_days = (end_date - start_date).days + 1  # Include both start and end date
    daily_rate = 25  # Fixed daily rate
    total_cost = daily_rate * total_days

    # Render reservation details page
    return render_template(
        'resource_confirmation.html', resource=resource, owner=owner, owner_user_id=owner_user_id, start_date=start_date.strftime('%B %d, %Y'), end_date=end_date.strftime('%B %d, %Y'), total_days=total_days, total_cost=total_cost, daily_rate=daily_rate, booking_id=booking_id
    )

# Search Functionality
@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.form.get('query', '')
    category = request.form.get('category', '')

    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('''SELECT * FROM Resources WHERE (title LIKE ? OR description LIKE ?)
                     AND (category LIKE ?)''', ('%' + query + '%', '%' + query + '%', '%' + category + '%'))
        results = c.fetchall()
    return render_template('search_results.html', results=results, query=query)

# Messaging System Conversations List
@app.route('/messages', methods=['GET'])
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Fetch unique conversations (either sender or receiver)
        c.execute('''SELECT DISTINCT CASE 
                         WHEN sender_id = ? THEN receiver_id 
                         ELSE sender_id 
                     END AS other_user_id, Users.name 
                     FROM Messages 
                     JOIN Users ON Users.user_id = CASE 
                         WHEN sender_id = ? THEN receiver_id 
                         ELSE sender_id 
                     END 
                     WHERE sender_id = ? OR receiver_id = ?''', 
                     (user_id, user_id, user_id, user_id))
        conversations = c.fetchall()

    # Set default receiver to the first conversation's ID if available
    receiver_id = conversations[0]['other_user_id'] if conversations else None

    return render_template('messages.html', conversations=conversations, current_user_id=user_id, receiver_id=receiver_id)

# Conversation View and Send Message
@app.route('/messages/<int:receiver_id>', methods=['GET', 'POST'])
def view_conversation(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Handling message submission
    if request.method == 'POST':
        message_content = request.form['content']
        if message_content:  # Ensure the message content is not empty
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with sqlite3.connect('projects.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO Messages (sender_id, receiver_id, content, timestamp)
                             VALUES (?, ?, ?, ?)''', (user_id, receiver_id, message_content, timestamp))
                conn.commit()
        return redirect(url_for('view_conversation', receiver_id=receiver_id))  # Reload the conversation page

    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Fetch all messages between the user and the receiver (both directions)
        c.execute('''SELECT Messages.*, Users.name AS sender_name, Users.profile_image
                     FROM Messages 
                     JOIN Users ON Messages.sender_id = Users.user_id
                     WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                     ORDER BY timestamp ASC''', (user_id, receiver_id, receiver_id, user_id))
        messages = c.fetchall()

        # Fetch conversations (define conversations here)
        c.execute('''SELECT DISTINCT CASE 
                         WHEN sender_id = ? THEN receiver_id 
                         ELSE sender_id 
                     END AS other_user_id, Users.name 
                     FROM Messages 
                     JOIN Users ON Users.user_id = CASE 
                         WHEN sender_id = ? THEN receiver_id 
                         ELSE sender_id 
                     END 
                     WHERE sender_id = ? OR receiver_id = ?''', 
                     (user_id, user_id, user_id, user_id))
        conversations = c.fetchall()

        # Fetch receiver's name and profile image
        c.execute('SELECT name, profile_image FROM Users WHERE user_id = ?', (receiver_id,))
        receiver = c.fetchone()

    # Redirect if receiver is not found
    if not receiver:
        flash("Receiver not found.")
        return redirect(url_for('messages'))

    # Renaming variable to avoid shadowing warning
    all_conversations = conversations

    return render_template(
        'messages.html', messages=messages, conversations=all_conversations, receiver_id=receiver_id, current_user_id=user_id, receiver_name=receiver['name'], receiver_image=receiver['profile_image']
    )

#Send Message
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']  # The sender's user ID
    receiver_id = request.form.get('receiver_id')  # The organizer's user ID
    content = request.form.get('content')  # The message content
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save the message to the database
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO Messages (sender_id, receiver_id, content, timestamp)
                     VALUES (?, ?, ?, ?)''', (user_id, receiver_id, content, timestamp))
        conn.commit()

    flash("Message sent successfully!")

    # Redirect to the conversation page with the organizer
    return redirect(url_for('view_conversation', receiver_id=receiver_id))

#Resources Page
@app.route('/resources', methods=['GET', 'POST'])
def resources():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.form.get('query', '')
    category = request.form.get('category', '')
    location = request.form.get('location', '')

    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('''SELECT * FROM Resources WHERE 
                     (title LIKE ? OR description LIKE ?)
                     AND (category LIKE ? OR ? = '')
                     AND (availability LIKE ? OR ? = '')''',
                  ('%' + query + '%', '%' + query + '%', '%' + category + '%', category,
                   '%' + location + '%', location))
        resources = c.fetchall()

    return render_template('resources.html', resources=resources, query=query, category=category, location=location)

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Connect to the database and delete the booking
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        # Delete the booking with matching booking_id and user_id
        c.execute('DELETE FROM bookings WHERE booking_id = ? AND user_id = ?', (booking_id, user_id))
        conn.commit()
    
    # Flash message to confirm the cancellation
    flash('Your resource booking has been canceled.')
    
    # Redirect back to the dashboard or a relevant page
    return redirect(url_for('dashboard'))


# Ratings and Reviews Logic on Rescoure
@app.route('/resource/<int:resource_id>/reviews', methods=['GET', 'POST'])
def resource_reviews(resource_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        rating = request.form['rating']
        comment = request.form['comment']
        reviewer_id = session['user_id']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            
            # Fetch the user_id of the resource owner
            c.execute('SELECT user_id FROM Resources WHERE resource_id = ?', (resource_id,))
            owner = c.fetchone()
            if owner:
                user_id = owner[0]  # The user_id of the resource owner
                
                # Insert the new review into the Reviews table
                c.execute('''INSERT INTO Reviews (user_id, reviewer_id, rating, comment, timestamp, resource_id)
                             VALUES (?, ?, ?, ?, ?, ?)''', (user_id, reviewer_id, rating, comment, timestamp, resource_id))
                conn.commit()
            else:
                # If the resource doesn't exist, show an error message
                flash("Resource not found.")
                return redirect(url_for('dashboard'))

        # Redirect to the dashboard after submitting the review
        return redirect(url_for('dashboard'))

    # Fetch all reviews for the specific resource, including reviewer details
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT Reviews.comment, Reviews.rating, Reviews.timestamp, Users.name AS reviewer_name, Resources.title AS resource_title
            FROM Reviews
            JOIN Users ON Reviews.reviewer_id = Users.user_id
            JOIN Resources ON Reviews.resource_id = Resources.resource_id
            WHERE Reviews.resource_id = ?
            ORDER BY Reviews.timestamp DESC
        ''', (resource_id,))
        reviews = c.fetchall()

    return render_template('resource_reviews.html', resource_id=resource_id, reviews=reviews)

# Community Events Page
@app.route('/community-events', methods=['GET', 'POST'])
def community_events():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        date = request.form.get('date')
        time = request.form.get('time')

        # Server-side validations
        if not title or len(title) > 100:
            error = "Title is required and must be 100 characters or fewer."
        elif not description or len(description) > 500:
            error = "Description is required and must be 500 characters or fewer."
        elif not location or len(location) > 100:
            error = "Location is required and must be 100 characters or fewer."
        elif not date:
            error = "Date is required."

        if error:
            flash(error)
            return render_template('events.html')

        user_id = session['user_id']
        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO CommunityEvents (title, description, location, date, time, user_id)
                         VALUES (?, ?, ?, ?, ?, ?)''', (title, description, location, date, time, user_id))
            conn.commit()

        return redirect(url_for('community_events'))

    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT CommunityEvents.*, Users.name AS organizer_name, Users.profile_image AS organizer_profile_image
            FROM CommunityEvents
            JOIN Users ON CommunityEvents.user_id = Users.user_id
        ''')
        events = c.fetchall()
        
    return render_template('events.html', events=events)

# Create Event Page
@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        date = request.form['date']
        time = request.form.get('time', '')

        user_id = session['user_id']

        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO CommunityEvents (user_id, title, description, location, date, time)
                         VALUES (?, ?, ?, ?, ?, ?)''', (user_id, title, description, location, date, time))
            conn.commit()
        return redirect(url_for('community_events'))

    return render_template('create_event.html')

# Event Details Page
@app.route('/event/<int:event_id>', methods=['GET', 'POST'])
def event_details(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Fetch event details
        c.execute('''SELECT CommunityEvents.*, Users.user_id AS organizer_id, Users.name AS organizer_name 
                     FROM CommunityEvents 
                     JOIN Users ON CommunityEvents.user_id = Users.user_id
                     WHERE event_id = ?''', (event_id,))
        event = c.fetchone()

        # Check if the event exists
        if not event:
            flash("Event not found.")
            return redirect(url_for('community_events'))
        
        # Check if the user has already RSVP'd
        c.execute('SELECT * FROM EventRSVPs WHERE event_id = ? AND user_id = ?', (event_id, user_id))
        user_rsvp = c.fetchone()

        # Handle RSVP submission
        if request.method == 'POST' and not user_rsvp:
            c.execute('INSERT INTO EventRSVPs (event_id, user_id) VALUES (?, ?)', (event_id, user_id))
            conn.commit()
            flash("You have successfully RSVP'd to this event.")
            return redirect(url_for('event_details', event_id=event_id))

        # Count the number of RSVPs for the event
        c.execute('SELECT COUNT(*) FROM EventRSVPs WHERE event_id = ?', (event_id,))
        attendee_count = c.fetchone()[0]

    return render_template(
        'event_details.html', event=event, attendee_count=attendee_count, user_rsvp=user_rsvp, organizer_id=event['organizer_id']  # Pass organizer_id to template
    )

#Profile Page:
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Fetch user information
        c.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = c.fetchone()

        # Fetch user reviews as the reviewed user
        c.execute('SELECT rating FROM Reviews WHERE user_id = ?', (user_id,))
        ratings = [int(row['rating']) for row in c.fetchall()]

    # Calculate average rating, rounded to one decimal place
    average_rating = round(sum(ratings) / len(ratings), 1) if ratings else 0

    return render_template('profile.html', user=user, average_rating=average_rating)

# Route for editing profile
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        location = request.form['location']
        
        # Check if a profile photo was uploaded
        profile_photo = request.files.get('profile_photo')
        filename = None
        if profile_photo and profile_photo.filename != '':
            filename = secure_filename(profile_photo.filename)
            profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update the user's profile in the database
        with sqlite3.connect('projects.db') as conn:
            c = conn.cursor()
            if filename:
                # Update with profile photo
                c.execute('''UPDATE Users SET name = ?, email = ?, location = ?, profile_image = ? WHERE user_id = ?''',
                          (name, email, location, filename, user_id))
            else:
                # Update without changing profile photo
                c.execute('''UPDATE Users SET name = ?, email = ?, location = ? WHERE user_id = ?''',
                          (name, email, location, user_id))
            conn.commit()
        
        flash("Profile updated successfully!")
        return redirect(url_for('profile'))

    # Fetch user data to pre-fill the form
    with sqlite3.connect('projects.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = c.fetchone()

    return render_template('edit_profile.html', user=user)

# Route for updating password
@app.route('/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Fetch the current password from the database
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password FROM Users WHERE user_id = ?', (user_id,))
        stored_password = c.fetchone()[0]

    # Check if the current password matches the stored password
    if not check_password_hash(stored_password, current_password):
        flash("Current password is incorrect.")
        return redirect(url_for('profile'))

    # Check if the new passwords match
    if new_password != confirm_password:
        flash("New passwords do not match.")
        return redirect(url_for('profile'))

    # Update the password in the database
    hashed_new_password = generate_password_hash(new_password)
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE Users SET password = ? WHERE user_id = ?', (hashed_new_password, user_id))
        conn.commit()

    flash("Password updated successfully!")
    return redirect(url_for('profile'))

#Canceal event RSVP
@app.route('/cancel_rsvp/<int:event_id>', methods=['POST'])
def cancel_rsvp(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    with sqlite3.connect('projects.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM EventRSVPs WHERE event_id = ? AND user_id = ?', (event_id, user_id))
        conn.commit()
    
    flash('Your RSVP has been canceled.')
    return redirect(url_for('dashboard'))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
