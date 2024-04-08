import sqlite3
from sqlite3 import Error

from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect

# This script imports all required modules for the functionality of the code below, for example:
# render_template - used to render the webpage
# Flask - used to import Flask tools.
# request - imports the ability to 'POST' and 'GET' from a database,. used for users.
# redirect - imports functionality to redirect user to a different page (usually when error occurs)

app = Flask(__name__)
bcrypt = Bcrypt(app)

DATABASE = ''

def open_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as err:
        print(err)
        return None

# Below is where the pages are rendered using an app.route() script and a render_template defined above.

@app.route('/')
def render_home_page():
    return render_template('home_page.html')


@app.route('/dictionary')
def render_dictionary_page():
    return render_template('dictionary_page.html')

@app.route('/login')
def render_login_page():

    return render_template('')

@app.route('/signup', methods=['POST','GET'])
def render_signup_page():
    if request.method == 'POST':
        print(request.form)
        first_name = request.form.get('first_name').title().strip()
        last_name = request.form.get('last_name').title().strip()
        email = request.form.get('email').title().strip()
        user_type = request.form.get('type').title().strip()
        password = request.form.get('password')
        password_two = request.form.get('password_two')

        if password != password_two:
            return redirect('/signup?error=Passwords+do+not+match+try+again')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+at+least+eight+characters+long')

        hashed_password = bcrypt.generate_password_hash(password)
        con = open_database(DATABASE)
        query = "INSERT INTO user (type, first_name, last_name, email, password) VALUES (?, ?, ? ,?)"
        cur = con.cursor()

        try:
            cur.execute(query, (user_type, first_name, last_name, email, hashed_password))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/signup?error=Email+is+already+in+use')

        con.commit()
        con.close()

        return redirect("/login")

    return render_template('signup.html')


if __name__ == '__main__':
    app.run()
