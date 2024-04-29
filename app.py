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
app.secret_key = "ueuywq9571"

DATABASE = 'C:/Users/20024/OneDrive - Wellington College/2024 20024 Programming and Database Assessment/Main Project Files/Project/database'

# make sure to add updoot system


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
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category, definition, level, user_id, word_image FROM dictionary'
    cur = con.cursor()
    cur.execute(query)
    dictionary_content = cur.fetchall()
    con.close()
    print(dictionary_content)
    return render_template('dictionary_page.html', dictionary=dictionary_content)


@app.route('/login')
def render_login_page():
    return render_template('login_page.html')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
    if request.method == 'POST':
        print(request.form)
        print(request.form.get('type'))
        first_name = request.form.get('fname').title().strip()
        last_name = request.form.get('lname').title().strip()
        email = request.form.get('email').title().strip()
        type = request.form.get('user_type')
        password = request.form.get('password')
        password_two = request.form.get('password_two')

        if password != password_two:
            return redirect('/signup?error=Passwords+do+not+match+try+again')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+at+least+eight+characters+long')

        hashed_password = bcrypt.generate_password_hash(password)
        con = open_database(DATABASE)
        query = "INSERT INTO users (type, first_name, last_name, email, password) VALUES (?, ?, ? ,? ,?)"
        cur = con.cursor()

        try:
            cur.execute(query, (type, first_name, last_name, email, hashed_password))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/signup?error=Email+is+already+in+use')

        con.commit()
        con.close()

        return redirect("/")

    return render_template('signup_page.html')


if __name__ == '__main__':
    app.run()
