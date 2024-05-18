import sqlite3
from sqlite3 import Error

from time import gmtime, strftime

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

# for home computer - C:/Users/georg/PycharmProjects/20024-2024-Programming-and-Database-Assessment/database
# for school computer - C:/Users/20024/OneDrive - Wellington College/2024 20024 Programming and Database Assessment/Main Project Files/Project/database

DATABASE = 'C:/Users/georg/PycharmProjects/20024-2024-Programming-and-Database-Assessment/database'


# make sure to add upvote system


def open_database(db_file):
    # This function is responsible for connecting to the external database that is found in the constant 'DATABASE' shown above.
    try:
        connection = sqlite3.connect(db_file)
        return connection
        # This above part of the function is responsible for the connection, and if the connection is unsuccessful,
        # the function will return the below error and will not return a connection.
    except Error as err:
        print(err)
        return None


def is_admin():
    # This script is responsible for determining if the user is an admin or not, and it does this by requesting
    # the state of the 'type' field for whatever user is currently in-session. It is a binary value, where 1 is
    # equal to 'teacher', and 0 is equal to 'student'. Having these as binary values as integers saves space and
    # reduces computing load.
    if session.get('type') == '1':
        print('Teacher user.')
        return True
    else:
        print('Student user.')
        return False


def is_logged_in():
    # Similar purpose to the is_admin() function above, but in this case it requests whether the current session's
    # user has an email or not, and as the email is a mandatory field, it means that if email is equal to 'None', it
    # means that the user is not logged in.
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


@app.route('/search', methods=['POST', 'GET'])
def render_search_page():
    if request.method == 'POST':
        print(request.form)
        search = request.form.get('search')
        print(search)

        # add inner join at some point

        # **THIS COMMENT WILL EXPLAIN ALL DATABASE OPENING, REQUESTING AND CLOSING SCRIPTS WITH MINOR CHANGES**
        # This specific select statement selects all the data from the 'dictionary' table where the word's maori
        # name or english name contains the word or letter written in the search field present in the search page.
        # This is done by specifying within the query execution statement exactly what these words should be compared
        # against.
        query = "SELECT * FROM dictionary WHERE maori_name LIKE ? OR english_name LIKE ?"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, ('%' + search + '%', '%' + search + '%',))
        search = cur.fetchall()
        con.close()
        print(search)

        # This below section serves to re-render the page with the new information present.
        return render_template('search_page.html', search_content=search, logged_in=is_logged_in(), is_admin=is_admin())

    # This is the original render of the page with no searched information present.
    return render_template('search_page.html', logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/delete/<word>', methods=['POST', 'GET'])
def render_delete_word_page(word):
    # This select statement selects a word from the dictionary that is equal to the word defined above that was
    # selected by the user via a link in the dictionary page. This select statement then posts the information of
    # that word to the page, and presents specifically the data for that word alone.
    if request.method == 'POST':
        con = open_database(DATABASE)
        print('This is before the delete happens.')
        print(word)
        query = 'DELETE FROM dictionary WHERE maori_name = ?'
        cur = con.cursor()
        cur.execute(query, (word, ))
        con.commit()
        con.close()
        print(word)
        print('This is after the delete happens.')
        return redirect('/dictionary?error=Word+successfully+deleted.')

    return render_template('delete_word.html', admin=is_admin(), logged_in=is_logged_in())


@app.route('/word/<word>')
def render_word_page(word):
    # This select statement selects a word from the dictionary that is equal to the word defined above that was
    # selected by the user via a link in the dictionary page. This select statement then posts the information of
    # that word to the page, and presents specifically the data for that word alone.
    con = open_database(DATABASE)
    query = 'SELECT * FROM dictionary WHERE maori_name LIKE ?'
    cur = con.cursor()
    print(word)
    cur.execute(query, (word,))
    word_info = cur.fetchall()
    con.close()
    print(word_info)
    return render_template('word_page.html', word=word, page_word=word_info, is_admin=is_admin(), logged_in=is_logged_in())


@app.route('/user/<user>')
def render_user_page(user):
    # This select statement selects a word from the dictionary that is equal to the word defined above that was
    # selected by the user via a link in the dictionary page. This select statement then posts the information of
    # that word to the page, and presents specifically the data for that word alone.
    con = open_database(DATABASE)
    query = 'SELECT user_id, type, first_name, last_name, email FROM users WHERE user_id LIKE ?'
    cur = con.cursor()
    cur.execute(query, (user,))
    user_info = cur.fetchall()
    con.close()
    print(user_info)
    return render_template('user_page.html', user=user_info, is_admin=is_admin(), logged_in=is_logged_in())


@app.route('/dictionary', methods=['POST', 'GET'])
def render_dictionary_page():
    # This select statement only needs to display the word's name in maori, as that is what is present on the link that
    # the user will click on to view the rest of the information about the word in the /word page.
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category_name, definition, level FROM dictionary INNER JOIN categories WHERE dictionary.category = categories.category_id'

    cur = con.cursor()
    cur.execute(query)
    dictionary_content = cur.fetchall()
    con.close()
    print(dictionary_content[1])
    print(dictionary_content)
    return render_template('dictionary_page.html', dictionary=dictionary_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/user_catalogue', methods=['POST', 'GET'])
def render_user_catalogue():
    # This select statement only needs to display the word's name in maori, as that is what is present on the link that
    # the user will click on to view the rest of the information about the word in the /word page.
    con = open_database(DATABASE)
    query = 'SELECT user_id, first_name, last_name FROM users'
    cur = con.cursor()
    cur.execute(query)
    user_content = cur.fetchall()
    con.close()
    print(user_content)
    return render_template('user_catalogue.html', users=user_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/dictionary_admin', methods=['POST', 'GET'])
def render_dictionary_admin():
    con = open_database(DATABASE)
    query_category = 'SELECT DISTINCT category_id, category_name FROM categories'
    cur = con.cursor()
    cur.execute(query_category)
    category = cur.fetchall()
    print(f'category = {category}')
    con.close()
    if request.method == 'POST':
        print(f'request.form = {request.form}')
        print(f"request.form.get('type') = {request.form.get('type')}")
        english_name = request.form.get('english_name').title().strip()
        maori_name = request.form.get('maori_name').title().strip()
        category = request.form.get('category').title().strip()
        definition = request.form.get('definition').capitalize().strip()
        level = request.form.get('level')
        time_added = strftime('%Y-%m-%d %H:%M:%S', gmtime())
        print(time_added)
        try:
            level = int(level)
        except ValueError:
            return redirect('/dictionary_admin?error=Please+enter+a+numeral+between+1+and+10')
        if level in range(1, 11):
            print(level)
        else:
            return redirect("/dictionary_admin?error=Choose+a+level+between+1+and+10")
        con = open_database(DATABASE)
        user_id = session.get('user_id')
        query = 'INSERT INTO dictionary (english_name, maori_name, category, definition, level, user_id, date_entered) VALUES (?, ?, ? ,? ,? ,? ,?)'
        cur = con.cursor()
        cur.execute(query, (english_name, maori_name, category, definition, level, user_id, time_added))

        con.commit()
        con.close()

        return redirect("/dictionary_admin?error=Addition+successful")

    return render_template('dictionary_admin.html', category=category, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/category_admin', methods=['POST', 'GET'])
def render_category_admin():
    con = open_database(DATABASE)
    query_category = 'SELECT category_name FROM categories'
    cur = con.cursor()
    cur.execute(query_category)
    category = cur.fetchall()
    print(f'category = {category}')
    con.close()
    if request.method == 'POST':
        print(f'request.form = {request.form}')
        new_category_name = request.form.get('category_name').title().strip()
        try:
            new_category_name = str(new_category_name)
        except IndexError:
            return redirect('/dictionary_admin?error=Please+enter+a+category+word')
        con = open_database(DATABASE)
        user_id = session.get('user_id')
        time_added = strftime('%Y-%m-%d %H:%M:%S', gmtime())
        print(time_added)
        query = 'INSERT INTO categories (category_name, user_id, date_entered) VALUES (?, ?, ?)'
        cur = con.cursor()
        cur.execute(query, (new_category_name, user_id, time_added))

        con.commit()
        con.close()

        return redirect("/dictionary_admin?error=Addition+successful")

    return render_template('category_admin.html', category=category, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/category', methods=['POST', 'GET'])
def render_category_page():
    con = open_database(DATABASE)
    query_category = 'SELECT DISTINCT category_id, category_name FROM categories'
    cur = con.cursor()
    cur.execute(query_category)
    category = cur.fetchall()
    print(category)
    con.close()
    if request.method == 'POST':
        print(request.form)
        category_chosen = request.form.get('category').capitalize().strip()
        print(category_chosen)
        con = open_database(DATABASE)
        query = 'SELECT maori_name, english_name, category_name, definition, level FROM dictionary INNER JOIN categories ON dictionary.category = categories.category_id WHERE category = ?'
        cur = con.cursor()
        cur.execute(query, (category_chosen,))
        dictionary_content_category = cur.fetchall()
        con.close()
        return render_template('category_page.html', dictionary_category=dictionary_content_category, category=category, logged_in=is_logged_in(), is_admin=is_admin())

    return render_template('category_page.html', category=category, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if is_logged_in():
        return redirect("/dictionary")
    print("Logging In...")
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        print(email)
        query = "SELECT user_id, type, first_name, password FROM users WHERE email = ?"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()

        if user_data is not None:
            print(user_data)

            try:
                user_id = user_data[0]
                type = user_data[1]
                first_name = user_data[2]
                db_password = user_data[3]
            except IndexError:
                return redirect("/login?error=Please+enter+a+correct+username+or+password")

            if not bcrypt.check_password_hash(db_password, password):
                return redirect(request.referrer + "?error=Email+or+password+are+invalid")

            session['email'] = email
            session['first_name'] = first_name
            session['user_id'] = user_id
            session['type'] = type

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
        print(type)

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

    return render_template('signup_page.html', logged_in=is_logged_in(), is_admin=is_admin())


if __name__ == '__main__':
    app.run()
