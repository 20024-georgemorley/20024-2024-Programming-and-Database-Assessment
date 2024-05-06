import sqlite3
from sqlite3 import Error

from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, session

# This script imports all required modules for the functionality of the code below, for example:
# render_template - used to render the webpage
# Flask - used to import Flask tools.
# request - imports the ability to 'POST' and 'GET' from a database, used for users.
# redirect - imports functionality to redirect user to a different page (usually when error occurs)

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "9571"

DATABASE = 'C:/Users/20024/OneDrive - Wellington College/2024 20024 Programming and Database Assessment/Main Project Files/Project/database'


# make sure to add upvote system


def open_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as err:
        print(err)
        return None


def is_admin():
    if session.get('type') != 'student':
        print('Teacher user.')
        return True
    else:
        print('Student user.')
        return False


def is_logged_in():
    if session.get('email') is None:
        print('Not logged in.')
        return False
    else:
        print('Logged in.')
        return True


# Below is where the pages are rendered using an app.route() script and a render_template defined above.


@app.route('/')
def render_home_page():
    return render_template('home_page.html', logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/search')
def render_search_page():
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category, definition, level, user_id, word_image FROM dictionary WHERE maori_name LIKE "% + search + %" OR english_name LIKE "% + search + %"'
    cur = con.cursor()
    cur.execute(query)
    search_query = cur.fetchall()
    con.close()
    print(search_query)
    return render_template('search_page.html', search=search_query, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/dictionary')
def render_dictionary_page():
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category, definition, level, user_id, word_image FROM dictionary'
    cur = con.cursor()
    cur.execute(query)
    dictionary_content = cur.fetchall()
    con.close()
    print(dictionary_content)
    return render_template('dictionary_page.html', dictionary=dictionary_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/dictionary_admin', methods=['POST', 'GET'])
def render_dictionary_admin():
    if request.method == 'POST':
        print(request.form)
        print(request.form.get('type'))
        english_name = request.form.get('english_name').title().strip()
        maori_name = request.form.get('maori_name').title().strip()
        category = request.form.get('category').title().strip()
        definition = request.form.get('definition').title().strip()
        level = request.form.get('level').title().strip()

        if level in range(1, 11):
            print(level)
        else:
            return redirect("/dictionary_admin?error=Choose+a+level+between+1+and+10")

        con = open_database(DATABASE)
        query = 'INSERT INTO dictionary (english_name, maori_name, category, definition, level) VALUES (?, ?, ? ,? ,?)'
        cur = con.cursor()
        cur.execute(query, (english_name, maori_name, category, definition, level))

        con.commit()
        con.close()

        return redirect("/dictionary")
    return render_template('dictionary_admin.html', logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if is_logged_in():
        return redirect("/dictionary")
    print("Logging In...")
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        print(email)
        query = "SELECT user_id, first_name, password FROM users WHERE email = ?"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()

        if user_data is not None:
            print(user_data)

            try:
                user_id = user_data[0]
                first_name = user_data[1]
                db_password = user_data[2]
            except IndexError:
                return redirect("/login?error=Please+enter+a+correct+username+or+password")

            if not bcrypt.check_password_hash(db_password, password):
                return redirect(request.referrer + "?error=Email+or+password+are+invalid")

            session['email'] = email
            session['first_name'] = first_name
            session['user_id'] = user_id

            print(session)
            return redirect('/')
        else:
            return redirect("/login?error=Email+does+not+exist.")

    return render_template('login_page.html', is_admin=is_admin())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=Thank+you+for+using+our+website!')
    return redirect('/')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
    if is_logged_in():
        return redirect("/dictionary")
    if request.method == 'POST':
        print(request.form)
        print(request.form.get('type'))
        first_name = request.form.get('fname').title().strip()
        last_name = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        type = request.form.get('type')
        password = request.form.get('password')
        password_two = request.form.get('password_two')

        if password != password_two:
            return redirect('/signup?error=Passwords+do+not+match+try+again')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+at+least+eight+characters+long')

        if type != 'student' or 'teacher':
            return redirect('/signup?error=Please+select+student+or+teacher')

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

    return render_template('signup_page.html', logged_in=is_logged_in(), is_admin=is_admin())


if __name__ == '__main__':
    app.run()
