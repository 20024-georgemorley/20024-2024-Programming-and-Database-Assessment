from flask import Flask, render_template, request, redirect

import sqlite3

from sqlite3 import Error

# from flask_bcrypt import Bcrypt

# This script imports all required modules for the functionality of the code below, for example:
# render_template - used to render the webpage
# Flask - used to import Flask tools.
# request - imports the ability to 'POST' and 'GET' from a database,. used for users.
# redirect - imports functionality to redirect user to a different page (usually when error occurs)

app = Flask(__name__)
# bcrypt = Bcrypt(app)

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

if __name__ == '__main__':
    app.run()
