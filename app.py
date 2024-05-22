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

# for home computer - C:/Users/georg/PycharmProjects/20024-2024-Programming-and-Database-Assessment/database for
# school computer - C:/Users/20024/OneDrive - Wellington College/2024 20024 Programming and Database Assessment/Main
# Project Files/Project/database

DATABASE = 'C:/Users/20024/OneDrive - Wellington College/2024 20024 Programming and Database Assessment/Main Project ' \
           'Files/Project/database'


# make sure to add upvote system


def open_database(db_file):
    # This function is responsible for connecting to the external database that is found in the constant 'DATABASE'
    # shown above.
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
    # This function serves to delete a word from the dictionary using the SQL DELETE FROM function. It requests the
    # word from the word_page, and deletes all words from the dictionary where the maori word for it is equal to the
    # maori word taken from the word_page. The user is then redirected back to the dictionary and is told that the
    # word was successfully deleted.
    if request.method == 'POST':
        con = open_database(DATABASE)
        query = 'DELETE FROM dictionary WHERE maori_name = ?'
        cur = con.cursor()
        cur.execute(query, (word, ))
        con.commit()
        con.close()
        return redirect('/dictionary?error=Word+successfully+deleted.')

    return render_template('delete_word.html', admin=is_admin(), logged_in=is_logged_in())


@app.route('/word/<word>')
def render_word_page(word):
    # This select statement selects a word from the dictionary that is equal to the word defined above that was
    # selected by the user via a link in the dictionary page. This select statement then posts the information of
    # that word to the page, and presents specifically the data for that word alone.
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category_name, definition, level, dictionary.user_id, dictionary.date_entered FROM ' \
            'dictionary INNER JOIN categories ON dictionary.category = categories.category_id WHERE maori_name LIKE ?'
    cur = con.cursor()
    print(word)
    cur.execute(query, (word,))
    word_info = cur.fetchall()
    con.close()
    print(word_info)
    return render_template('word_page.html', word=word, page_word=word_info, is_admin=is_admin(), logged_in=is_logged_in())


@app.route('/category/<category>', methods=['POST', 'GET'])
def render_category_page(category):
    # This function serves to request data from the database where the category_id of each word is compared against the
    # data taken from the page (category). This will request all information from the database where the category_id of
    # the information is equal to the inputted category.
    con = open_database(DATABASE)
    query = 'SELECT * FROM categories WHERE category_id LIKE ?'
    cur = con.cursor()
    cur.execute(query, (category,))
    category_info = cur.fetchall()
    con.close()
    print(category_info)
    if request.method == 'POST':
        # This area of the function allows the user to rename the category that is shown on the page. The function
        # requests the user's input from a textbox, and assigns it to 'category_rename'. This is used to update the
        # category name of an entry in the category table where the category ID of the category is equal to
        # 'category', a variable taken from earlier in the function. It then commits this update and closes the
        # database while redirecting the user back to the main category catalogue page.
        print(f'request.form = {request.form}')
        category_rename = request.form.get('category_rename')
        print(category_rename)
        con = open_database(DATABASE)
        rename_query = 'UPDATE categories SET category_name = ? WHERE category_id = ?'
        cur = con.cursor()
        cur.execute(rename_query, (category_rename, category, ))
        con.commit()
        con.close()
        return redirect('/category_catalogue?error=Category+successfully+renamed.')

    return render_template('category_page.html', category=category_info, is_admin=is_admin(), logged_in=is_logged_in())


@app.route('/user/<user>')
def render_user_page(user):
    # This function works identically to the word_page function above, except instead of searching the dictionary
    # table, it searches the users table instead. Any explanations about how the SQL works specifically is in the
    # word_page function.
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
    # This select statement only needs to display the word's name in maori, as that is what is present on the link
    # that the user will click on to view the rest of the information about the word in the /word page. There is also
    # an inner join present that is used to display the name of the category, as opposed to just its category ID,
    # the field present in the dictionary table. The inner join compares the values of the category_id in the
    # categories table and category field in the dictionary table, and joins the tables if there is a parity between
    # any of the values. This can then be used to request values from the categories table, hence the 'category_name'
    # value not existing in the dictionary table but only in the categories table.
    con = open_database(DATABASE)
    query = 'SELECT maori_name, english_name, category_name, definition, level FROM dictionary INNER JOIN categories ' \
            'WHERE dictionary.category = categories.category_id'
    cur = con.cursor()
    cur.execute(query)
    dictionary_content = cur.fetchall()
    con.close()
    print(dictionary_content[1])
    print(dictionary_content)
    return render_template('dictionary_page.html', dictionary=dictionary_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/user_catalogue', methods=['POST', 'GET'])
def render_user_catalogue():
    # This functions serves to display all the users of the website, and it simply requests the user_id, first_name and
    # last_name from the database and displays it.
    con = open_database(DATABASE)
    query = 'SELECT user_id, first_name, last_name FROM users'
    cur = con.cursor()
    cur.execute(query)
    user_content = cur.fetchall()
    con.close()
    print(user_content)
    return render_template('user_catalogue.html', users=user_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/category_catalogue', methods=['POST', 'GET'])
def render_category_catalogue():
    # This functions the same way as the user_catalogue function, except it selects the category_id and category_name
    # from the categories table instead of from the users table.
    con = open_database(DATABASE)
    query = 'SELECT category_id, category_name FROM categories'
    cur = con.cursor()
    cur.execute(query)
    category_content = cur.fetchall()
    con.close()
    print(category_content)
    return render_template('category_catalogue.html', categories=category_content, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/dictionary_admin', methods=['POST', 'GET'])
def render_dictionary_admin():
    # This function serves as the way that the user (teacher user only) can add words to the dictionary,
    # and also contains a link to the category_admin table where they can add a category. This first part of the
    # function simply displays the categories for use in the dropdown menu, showing both the name of the category and
    # its ID to provide more information to the user.
    con = open_database(DATABASE)
    query_category = 'SELECT DISTINCT category_id, category_name FROM categories'
    cur = con.cursor()
    cur.execute(query_category)
    category = cur.fetchall()
    print(f'category = {category}')
    con.close()
    if request.method == 'POST':
        # This part of the function is used to request the details from the text boxes present in the dictionary
        # admin page, and they are used to specify the details of the word that will be added. The inputs from the
        # text boxes are converted into variables using a request.form.get function and are adjusted in order to make
        # them correspond to the nature of the words in the database. A series of checks are then made to verify
        # certain details about the inputs, such as ensuring that the level value is a number between 1 and 10
        # inclusive. There is also a function that requests the current time which will be added into the database
        # alongside the inputs. The function then inserts these values into the dictionary where they correspond to
        # specific values within the dictionary.
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
            # Returns if the level value is not an integer.
            return redirect('/dictionary_admin?error=Please+enter+a+numeral+between+1+and+10')
        if level in range(1, 11):
            print(level)
        else:
            # Error regarding number being between 1 and 10 inclusive
            return redirect("/dictionary_admin?error=Choose+a+level+between+1+and+10")
        con = open_database(DATABASE)
        user_id = session.get('user_id')
        query = 'INSERT INTO dictionary (english_name, maori_name, category, definition, level, user_id, ' \
                'date_entered) VALUES (?, ?, ? ,? ,? ,? ,?)'
        cur = con.cursor()
        cur.execute(query, (english_name, maori_name, category, definition, level, user_id, time_added))
        # The values from the text boxes correspond to fields within the dictionary table.
        con.commit()
        con.close()
        # A redirect happens alongside an 'error' message to show that the addition was successful.
        return redirect("/dictionary_admin?error=Addition+successful")

    return render_template('dictionary_admin.html', category=category, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/category_admin', methods=['POST', 'GET'])
def render_category_admin():
    # Works similarly to the dictionary admin function, except that it requests the categories from the database instead
    # of the words.
    con = open_database(DATABASE)
    query_category = 'SELECT category_name FROM categories'
    cur = con.cursor()
    cur.execute(query_category)
    category = cur.fetchall()
    print(f'category = {category}')
    con.close()
    if request.method == 'POST':
        # This area of the function requests the user's input from the category input text boxes on the html page and
        # adds the input to the categories table alongside validating whether it is a string and requesting the
        # user_id and what date and time the category was added.
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
def render_category_filter_page():
    # This page gives the user the ability to browse the dictionary but filtered by category. The first part of the
    # function requests the category id and name from the categories table that will be displayed on the dropdown
    # menu to select the category filter. The second part selects all the data from the dictionary table where the
    # word's category is equal to the category specified by the user in the dropdown menu.
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
        query = 'SELECT maori_name, english_name, category_name, definition, level FROM dictionary INNER JOIN ' \
                'categories ON dictionary.category = categories.category_id WHERE category = ?'
        cur = con.cursor()
        cur.execute(query, (category_chosen,))
        dictionary_content_category = cur.fetchall()
        con.close()
        # Re-renders the page in order to display the new data that has been filtered.
        return render_template('category_filter_page.html', dictionary_category=dictionary_content_category, category=category, logged_in=is_logged_in(), is_admin=is_admin())

    return render_template('category_filter_page.html', category=category, logged_in=is_logged_in(), is_admin=is_admin())


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    # This page allows the user to login. It works by requesting the data that the user added into the text boxes and
    # comparing it against all the records inside the users table. It has to then decrypt the hashed password as the
    # password that the user types in and the encrypted password will not be equal. If program decrypts the password
    # before it is equal to the user's input, then it switches the logged_in function to true and returns to the home
    # page.
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
    # The session.pop command returns the session to a state prior to the user logging in. It then returns the user to
    # the home page and provides a successful logout message.
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=Thank+you+for+using+our+website!')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
    # This page allows the user to add a new user to the website. It requests the user's inputs from the signup page,
    # and stores them as variables. It then ensures that the user's first and second password entries are equal,
    # and that the length of their password is greater than 8 characters. It then generates an encrypted password
    # using the password that the user entered, and then inserts all the values (replacing password and password_two
    # with an encrypted password) into the users table. It then returns them to the home page where they can proceed
    # to log in with their new login.
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
