from flask import Flask, render_template, request, redirect

import sqlite3

from sqlite3 import Error

from flask_bcrypt import Bcrypt

# This script imports all required modules for the functionality of the code below, for example:
# render_template - used to render the webpage
# Flask - used to import Flask tools.
# request - imports the ability to 'POST' and 'GET' from a database,. used for users.
# redirect - imports functionality to redirect user to a different page (usually when error occurs)

app = Flask(__name__)
bcrypt = Bcrypt(app)

DATABASE = 'C:/Users/20024/PycharmProjects/20024-2024-Programming-and-Database-Assessment/database'


def open_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as err:
        print(err)
        return None

def logged_in():
    if session.get("email") is None:
        print("You are not logged in.")
        return False
    else:
        print("You are logged in.")
        return True


# Below is where the pages are rendered using an app.route() script and a render_template defined above.

@app.route('/')
def render_home_page():
    return render_template('home_page.html')


@app.route('/dictionary')
def render_dictionary_page():
    return render_template('dictionary_page.html')


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if logged_in():
        return redirect('/dictionary/1')
    print("Logging in...")
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        print(email)
        query = """SELECT id, first_name, password FROM customer WHERE email = ?"""
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email, ))
        user_data = cur.fetchall()
        con.close()
        print(user_data)
        try:
            user_id = user_data[0]
            first_name = user_data[1]
            last_name = user_data[2]
        except IndexError:
            return redirect("/login?error=Invalid+username+or+password")
            

if __name__ == '__main__':
    app.run()
