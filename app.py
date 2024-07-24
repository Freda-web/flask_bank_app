from flask import Flask, render_template, redirect, url_for, flash, request, session # type: ignore
from flask_bcrypt import Bcrypt # type: ignore
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user # type: ignore
import mysql.connector # type: ignore
from mysql.connector import Error # type: ignore

app = Flask(__name__, '/static')
app.config['SECRET_KEY'] = 'AptechLekki'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# database connection
def get_db_connection():
    connection = mysql.connector.connect(
        host = 'localhost',
        database = 'db_bank',
        username = 'root',
        password = 'admin'
    )
    return connection

# user class
class User(UserMixin):
    # construction
    def __init__(self, accountNo, username, email, password, balance):
        self.accountNo = accountNo
        self.username = username
        self.email = email
        self.password = password
        self.balance = balance

    @staticmethod
    def get(user_accountNo):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE accountNo = %s', (user_accountNo, ))
        user_data = cursor.fetchone()
        cursor.close()
        connection.close()

        if user_data:
            return User(**user_data)
        return None

    @staticmethod
    def get_by_email(email):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user_data = cursor.fetchone()
        cursor.close()
        connection.close()

        if user_data:
            return User(**user_data)
        return None

    def get_id(self):
           return (self.accountNo)

@login_manager.user_loader
def load_user(user_accountNo):
    return User.get(user_accountNo)

# home
@app.route('/')
@app.route('/home', endpoint='home')
def home():
    return render_template('home.html')


# login
@app.route('/login', methods=['POST', 'GET'], endpoint='login')
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.get_by_email(email)
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Invalid login details", "danger")
    return render_template('login.html')

# register
@app.route('/register', methods=['POST', 'GET'], endpoint="register")
def register():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute('INSERT INTO users(username, email, password) VALUES(%s, %s, %s)', (username, email, hashed_password))
            connection.commit()
            cursor.close()
            connection.close()
            flash("Your account has been created successfully!", "success")
            return redirect(url_for('login'))
        except Error as e:
            flash(f"Error: {e}", "danger")
    return render_template('register.html')

# deposit
@app.route('/deposit', methods = ['POST', 'GET'], endpoint='deposit')
@login_required
def deposit():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            'UPDATE users SET balance = balance + %s WHERE accountNo = %s', (amount, current_user.accountNo)
        )
        connection.commit()
        cursor.close()
        flash('Deposit successful!', 'success')
        return redirect(url_for('account'))
    return render_template('deposit.html')

# withdraw
@app.route('/withdraw', methods = ['POST', 'GET'], endpoint='withdraw')
@login_required
def deposit():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        if current_user.balance >= amount:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                'UPDATE users SET balance = balance - %s WHERE accountNo = %s', (amount, current_user.accountNo)
            )
            connection.commit()
            cursor.close()
            flash('Withdrawal successful!', 'success')
        else:
            flash('Insufficient fund!', 'danger')

        return redirect(url_for('account'))
    return render_template('withdraw.html')

# account
@app.route('/account', endpoint='account')
@login_required
def account():
    return render_template('account.html')

# logout
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    flash("You logged out successfully!!")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)