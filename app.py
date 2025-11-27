from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import MySQLdb
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from random import randint
from datetime import datetime, timedelta
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__, static_folder='static')


app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not set")



@app.after_request
def add_cache_control_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, s-maxage=0, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# BREVO CONFIG

configuration = sib_api_v3_sdk.Configuration()
SENDINBLUE_API_KEY = os.getenv("SENDINBLUE_API_KEY")

if not SENDINBLUE_API_KEY:
    raise RuntimeError("SENDINBLUE_API_KEY environment variable is not set")

configuration.api_key['api-key'] = SENDINBLUE_API_KEY


SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME")

if not SENDER_EMAIL or not SENDER_NAME:
    raise RuntimeError("SENDER_EMAIL and SENDER_NAME must be set in .env")



UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "locallhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB")
app.config['MYSQL_PORT'] = int(os.getenv("MYSQL_PORT", "3306"))
app.config['MYSQL_SSL_CA'] = os.getenv("MYSQL_SSL_CA")  

if not app.config['MYSQL_USER'] or not app.config['MYSQL_PASSWORD'] or not app.config['MYSQL_DB']:
    raise RuntimeError("MySQL environment variables (MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB) must be set")


mysql = MySQL(app)


#routes

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            return "Passwords do not match.", 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        existing_user = cur.fetchone()
        cur.close()

        if existing_user:
            return "Email already registered.", 400

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                    (name, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session['user_logged_in'] = True
            session['user_name'] = user[1]
            session['user_id'] = user[0]
            return redirect(url_for('main'))
        else:
            flash("Invalid email or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/main")
def main():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE status = 'active' ORDER BY RAND() LIMIT 10")
    random_products = cursor.fetchall()

    cursor.execute("SELECT DISTINCT category FROM products WHERE status = 'active'")
    categories = [row['category'] for row in cursor.fetchall()]

    category_products = {}
    for category in categories:
        cursor.execute("SELECT * FROM products WHERE category = %s AND status = 'active'", (category,))
        category_products[category] = cursor.fetchall()

    cursor.close()
    return render_template('main.html', random_products=random_products,
                           category_products=category_products, categories=categories)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE username = %s", [username])
        admin = cur.fetchone()
        cur.close()

        if admin and check_password_hash(admin[2], password):
            session['admin_logged_in'] = True
            session['admin_id'] = admin[0]
            return redirect(url_for('add_product'))
        else:
            flash("Invalid credentials.")

    return render_template('login_admin.html')

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("You must be logged in to add items to cart.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

   
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if product:
       
        cursor.execute("SELECT * FROM cart WHERE user_id = %s AND product_id = %s",
                       (user_id, product_id))
        existing_item = cursor.fetchone()

        if existing_item:
            new_quantity = existing_item['quantity'] + 1
            cursor.execute("UPDATE cart SET quantity = %s WHERE user_id = %s AND product_id = %s",
                           (new_quantity, user_id, product_id))
        else:
            cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                           (user_id, product_id, 1))

        mysql.connection.commit()
        flash("Item added to cart successfully!") 
    else:
        flash("Product not found.")

    cursor.close()
    
    return redirect(request.referrer or url_for('main'))

@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash("You must be logged in to view cart.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT cart.id, cart.quantity, products.name, products.price, products.image_url
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = %s
    """, (user_id,))
    cart_items = cursor.fetchall()

    cursor.execute("""
        SELECT SUM(quantity) AS cart_count
        FROM cart
        WHERE user_id = %s
    """, (user_id,))
    cart_count = cursor.fetchone()['cart_count'] or 0

    total_price_value = sum(item['price'] * item['quantity'] for item in cart_items)

    return render_template('cart.html', cart=cart_items,
                           total_price=total_price_value, cart_count=cart_count)

@app.route('/remove_from_cart/<int:item_id>')
def remove_from_cart(item_id):
    if 'user_id' not in session:
        flash("You must be logged in to remove items.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM cart WHERE user_id = %s AND id = %s",
                   (user_id, item_id))
    mysql.connection.commit()

    return redirect(url_for('view_cart'))

@app.route('/update_quantity/<int:item_id>', methods=['POST'])
def update_quantity(item_id):
    if 'user_id' not in session:
        flash("You must be logged in to update quantity.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    new_quantity = int(request.form.get('quantity'))

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE cart SET quantity = %s WHERE user_id = %s AND id = %s",
                   (new_quantity, user_id, item_id))
    mysql.connection.commit()

    return redirect(url_for('view_cart'))

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        product_name = request.form['name']
        product_price = request.form['price']
        product_description = request.form['description']
        product_status = request.form['status']
        product_category = request.form['category']

        if 'image' not in request.files:
            flash("No file part")
            return redirect(request.url)

        product_image = request.files['image']
        if product_image.filename == '':
            flash("No selected file")
            return redirect(request.url)

        filename = secure_filename(product_image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        product_image.save(image_path)

        cur = mysql.connection.cursor()
        cur.execute("""INSERT INTO products 
            (name, price, description, status, category, image_url) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (product_name, product_price, product_description,
             product_status, product_category, image_path))
        mysql.connection.commit()
        cur.close()

        flash("Product added successfully!")
        return redirect(url_for('add_product'))

    return render_template('add_product.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("You must be logged in.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    return render_template('profile.html', user=user)

@app.route('/edit_user_details', methods=['GET', 'POST'])
def edit_user_details():
    if 'user_id' not in session:
        flash("You must be logged in.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']  
        street = request.form['street']
        city = request.form['city']
        state = request.form['state']
        pincode = request.form['pincode']

        address = f"{street}, {city}, {state}, {pincode}"

        cursor.execute("""
            UPDATE users
            SET name = %s, mobile = %s, address = %s
            WHERE id = %s
        """, (name, mobile, address, user_id))

        mysql.connection.commit()
        flash("Details updated!", "success")
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    return render_template('user_details.html', user=user)

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'user_id' not in session:
        flash("You must be logged in.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], current_password):
            if new_password == confirm_password:
                hashed_new_password = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                               (hashed_new_password, user_id))
                mysql.connection.commit()
                flash("Password updated!", "success")
                return redirect(url_for('profile'))
            else:
                flash("New passwords do not match.", "error")
        else:
            flash("Incorrect current password.", "error")

    return render_template('update_user_password.html')

@app.route('/update_admin_password', methods=['GET', 'POST'])
def update_admin_password():
    if 'admin_logged_in' not in session:
        flash("You must be logged in.")
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        admin_id = session.get('admin_id')
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT password FROM admin WHERE id = %s", (admin_id,))
        admin = cursor.fetchone()

        if admin and check_password_hash(admin['password'], current_password):
            if new_password == confirm_password:
                hashed_new_password = generate_password_hash(new_password)
                cursor.execute("UPDATE admin SET password = %s WHERE id = %s",
                               (hashed_new_password, admin_id))
                mysql.connection.commit()
                flash("Password updated!", "success")
                return redirect(url_for('add_product'))
            else:
                flash("Passwords do not match.", "error")
        else:
            flash("Incorrect password.", "error")

    return render_template('update_admin.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            otp = randint(100000, 999999)
            expiration_time = datetime.now() + timedelta(minutes=3)

            cursor.execute("""
                INSERT INTO otp_verification (email, otp, expiration_time)
                VALUES (%s, %s, %s)
            """, (email, otp, expiration_time))
            mysql.connection.commit()
            cursor.close()

            session['otp_email'] = email

            try:
                api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
                    sib_api_v3_sdk.ApiClient(configuration)
                )
                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                    to=[{"email": email}],
                    sender={"email": SENDER_EMAIL, "name": SENDER_NAME},
                    subject="Password Reset OTP",
                    html_content=f"<html><body><p>Your OTP is: <strong>{otp}</strong></p></body></html>"
                )
                api_instance.send_transac_email(send_smtp_email)
                flash("OTP has been sent to your email.", "success")
                return redirect(url_for('get_otp'))

            except ApiException as e:
                flash(f"Error sending email: {e}", "error")
        else:
            flash("This email is not registered.", "error")

    return render_template('forgot_pass.html')

@app.route('/get_otp', methods=['GET', 'POST'])
def get_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp').strip()
        email = session.get('otp_email')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM otp_verification WHERE email = %s AND otp = %s",
            (email, entered_otp)
        )
        otp_record = cursor.fetchone()

        if otp_record:
            expiration_time = otp_record['expiration_time']
            if datetime.now() < expiration_time:
                cursor.execute("DELETE FROM otp_verification WHERE email = %s", (email,))
                mysql.connection.commit()
                cursor.close()
                return redirect(url_for('reset_password'))
            else:
                flash("OTP has expired.", "error")
                cursor.execute("DELETE FROM otp_verification WHERE email = %s", (email,))
                mysql.connection.commit()
        else:
            flash("Invalid OTP.", "error")

        cursor.close()

    return render_template('get_otp.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    email = session.get('otp_email')

    if email:
        otp = randint(100000, 999999)
        expiration_time = datetime.now() + timedelta(minutes=3)

        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE otp_verification
            SET otp = %s, expiration_time = %s
            WHERE email = %s
        """, (otp, expiration_time, email))
        mysql.connection.commit()
        cursor.close()

        try:
            api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
                sib_api_v3_sdk.ApiClient(configuration)
            )
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": email}],
                sender={"email": SENDER_EMAIL, "name": SENDER_NAME},
                subject="Password Reset OTP",
                html_content=f"<html><body><p>Your new OTP is: <strong>{otp}</strong></p></body></html>"
            )
            api_instance.send_transac_email(send_smtp_email)
            flash("New OTP sent.", "success")

        except ApiException as e:
            flash(f"Error sending email: {e}", "error")

    return redirect(url_for('get_otp'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        email = session.get('otp_email')

        if new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s",
                           (hashed_password, email))
            mysql.connection.commit()
            cursor.close()

            flash("Password updated!", "success")
            return redirect(url_for('login'))
        else:
            flash("Passwords do not match.", "error")

    return render_template('reset.html')

@app.route('/search')
def search():
    query = request.args.get('query', '')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT * FROM products WHERE name LIKE %s AND status = 'active'",
        (f"%{query}%",)
    )
    search_results = cursor.fetchall()
    cursor.close()

    if not search_results:
        flash("No products found.", "info")

    return render_template('search.html', query=query, search_results=search_results)

@app.route('/filter')
def filter():
    category = request.args.get('category')

    if not category:
        flash("Category not specified.", "error")
        return redirect(url_for('main'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT * FROM products WHERE category = %s AND status = %s",
        (category, 'active')
    )
    category_products = cursor.fetchall()
    cursor.close()

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT DISTINCT category FROM products WHERE status = 'active'")
    categories = [row['category'] for row in cursor.fetchall()]
    cursor.close()

    return render_template('filter.html', category=category,
                           products=category_products, categories=categories)

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute("""
        SELECT cart.product_id, cart.quantity, products.price 
        FROM cart 
        JOIN products ON cart.product_id = products.id 
        WHERE cart.user_id = %s
    """, (user_id,))
    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Your cart is empty.")
        return redirect(url_for('view_cart'))

    
    for item in cart_items:
        cursor.execute("""
            INSERT INTO orders (user_id, product_id, quantity, price, status, order_date) 
            VALUES (%s, %s, %s, %s, 'Ordered', NOW())
        """, (user_id, item['product_id'], item['quantity'], item['price']))
    
    
    cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Items ordered successfully!")
    return redirect(url_for('orders'))

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute("""
        SELECT orders.id, orders.status, orders.price, orders.quantity, orders.order_date, 
               products.name, products.image_url 
        FROM orders 
        JOIN products ON orders.product_id = products.id 
        WHERE orders.user_id = %s 
        ORDER BY orders.order_date DESC
    """, (user_id,))
    my_orders = cursor.fetchall()
    cursor.close()

    return render_template('orders.html', orders=my_orders)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
