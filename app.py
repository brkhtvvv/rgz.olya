from flask import Flask, request, jsonify, session, render_template, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jsonrpc import JSONRPC
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from werkzeug.utils import secure_filename
import sqlite3
from os import path

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')

jsonrpc = JSONRPC(app, '/api')
UPLOAD_FOLDER = 'static/avatars'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='olga_barkhatova_knowledge_bace',
            user='olga_barkhatova_knowledge_bace',
            password='123'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    return conn, cur

def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

@app.route('/')
def main():
    try:
        conn, cur = db_connect()
        if 'user_id' in session:
            cur.execute("""
                SELECT ads.id, ads.title, ads.content, users.fullname AS author, users.email
                FROM ads
                JOIN users ON ads.user_id = users.id;
            """)
        else:
            cur.execute("""
                SELECT ads.id, ads.title, ads.content, users.fullname AS author
                FROM ads
                JOIN users ON ads.user_id = users.id;
            """)
        ads = cur.fetchall()
        db_close(conn, cur)
        return render_template('index.html', ads=ads)
    except Exception as e:
        return f"An error occurred: {str(e)}"







@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = generate_password_hash(request.form['password'])
        fullname = request.form['fullname']
        email = request.form['email']
        about = request.form.get('about', '')
        avatar = request.files['avatar']

        filename = secure_filename(avatar.filename)
        avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn, cur = db_connect()

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("INSERT INTO users (login, password, fullname, email, about, avatar) VALUES (%s, %s, %s, %s, %s, %s);",
                        (login, password, fullname, email, about, filename))
        else:
            cur.execute("INSERT INTO users (login, password, fullname, email, about, avatar) VALUES (?, ?, ?, ?, ?, ?);",
                        (login, password, fullname, email, about, filename))
        db_close(conn, cur)

        # Перенаправляем на главную страницу после регистрации
        return redirect(url_for('main'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        conn, cur = None, None  # Инициализация переменных
        try:
            conn, cur = db_connect()
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
            else:
                cur.execute("SELECT * FROM users WHERE login=?;", (login,))
            user = cur.fetchone()

            if user and check_password_hash(user['password'], password):  # Используем user['password']
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin'] if 'is_admin' in user.keys() else False
                return redirect(url_for('main'))
            else:
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            print(f"Error during login: {e}")
            return render_template('login.html', error=f"Error: {str(e)}")
        finally:
            if conn and cur:
                db_close(conn, cur)  # Гарантируем, что соединение закрывается корректно
    return render_template('login.html')




@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main'))



@jsonrpc.method('admin.delete_user')
def delete_user(user_id: int):
    if not session.get('is_admin'):
        return {'error': 'Unauthorized'}
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id=%s;", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id=?;", (user_id,))
    db_close(conn, cur)
    return {'success': 'User deleted'}

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/ads')
def ads():
    try:
        conn, cur = db_connect()
        cur.execute("""
            SELECT ads.id, ads.title, ads.content, users.fullname AS author, users.email
            FROM ads
            JOIN users ON ads.user_id = users.id;
        """)
        ads = cur.fetchall()
        db_close(conn, cur)
        return render_template('ads.html', ads=ads)

    except Exception as e:
        print(f"Error fetching ads: {e}")
        return "Internal Server Error", 500


@app.route('/create_ad', methods=['GET', 'POST'])
def create_ad():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']

        conn, cur = db_connect()

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("INSERT INTO ads (title, content, user_id) VALUES (%s, %s, %s);", (title, content, user_id))
        else:
            cur.execute("INSERT INTO ads (title, content, user_id) VALUES (?, ?, ?);", (title, content, user_id))
        db_close(conn, cur)
        return redirect(url_for('profile'))

    return render_template('create_ad.html')


@app.route('/edit_ad/<int:ad_id>', methods=['GET', 'POST'])
def edit_ad(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = cur.fetchone()

    if ad is None or ad['user_id'] != session['user_id']:  # Используем ad['user_id']
        return redirect(url_for('main'))  

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("UPDATE ads SET title=%s, content=%s WHERE id=%s;", (title, content, ad_id))
        else:
            cur.execute("UPDATE ads SET title=?, content=? WHERE id=?;", (title, content, ad_id))
        db_close(conn, cur)
        return redirect(url_for('profile'))

    db_close(conn, cur)
    return render_template('edit_ad.html', ad=ad)

@app.route('/delete_ad/<int:ad_id>', methods=['POST'])
def delete_ad(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = cur.fetchone()

    if ad is None or ad['user_id'] != session['user_id']:  # Используем ad['user_id']
        return redirect(url_for('main'))

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
    db_close(conn, cur)
    return redirect(url_for('profile'))

@jsonrpc.method('ad.create')
def create_ad_rpc(title: str, content: str):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}
    
    user_id = session['user_id']
    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO ads (title, content, user_id) VALUES (%s, %s, %s);", (title, content, user_id))
    else:
        cur.execute("INSERT INTO ads (title, content, user_id) VALUES (?, ?, ?);", (title, content, user_id))
    db_close(conn, cur)
    return {'success': 'Ad created'}

@jsonrpc.method('ad.edit')
def edit_ad_rpc(ad_id: int, title: str, content: str):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}
    
    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = cur.fetchone()

    if ad is None or ad['user_id'] != session['user_id']:
        return {'error': 'Unauthorized'}

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("UPDATE ads SET title=%s, content=%s WHERE id=%s;", (title, content, ad_id))
    else:
        cur.execute("UPDATE ads SET title=?, content=? WHERE id=?;", (title, content, ad_id))
    db_close(conn, cur)
    return {'success': 'Ad updated'}

@jsonrpc.method('ad.delete')
def delete_ad_rpc(ad_id: int):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}
    
    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = cur.fetchone()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
    db_close(conn, cur)
    return {'success': 'Ad deleted'}

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        print("User not logged in")
        return redirect(url_for('login'))

    conn, cur = db_connect()
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (session['user_id'],))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (session['user_id'],))
    user = cur.fetchone()

    if current_app.config['DB_TYPE'] == 'postgres':    
        cur.execute("""
            SELECT * FROM ads WHERE user_id=%s;
        """, (session['user_id'],))
    else:
        cur.execute("""
            SELECT * FROM ads WHERE user_id=?;
        """, (session['user_id'],))
    ads = cur.fetchall()

    db_close(conn, cur)

    if user:
        return render_template('profile.html', user=user, ads=ads)
    else:
        print("User not found in database")
        return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (session['user_id'],))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (session['user_id'],))
    user = cur.fetchone()

    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        about = request.form.get('about', '')
        avatar = request.files.get('avatar')

        if avatar:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET fullname=%s, email=%s, about=%s, avatar=%s WHERE id=%s;",
                            (fullname, email, about, filename, session['user_id']))
            else:
                cur.execute("UPDATE users SET fullname=?, email=?, about=?, avatar=? WHERE id=?;",
                            (fullname, email, about, filename, session['user_id']))
        else:

            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET fullname=%s, email=%s, about=%s WHERE id=%s;",
                            (fullname, email, about, session['user_id']))
            else:
                cur.execute("UPDATE users SET fullname=?, email=?, about=? WHERE id=?;",
                            (fullname, email, about, session['user_id']))

        db_close(conn, cur)
        return redirect(url_for('profile'))

    db_close(conn, cur)
    return render_template('edit_profile.html', user=user)

@app.route('/users')
def users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    try:
        conn, cur = db_connect()
        cur.execute("SELECT * FROM users;")
        users = cur.fetchall()
        db_close(conn, cur)
        return render_template('users.html', users=users)
    except Exception as e:
        return f"An error occurred: {str(e)}"
    

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    try:
        conn, cur = db_connect()

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("DELETE FROM users WHERE id=%s;", (user_id,))
        else:
            cur.execute("DELETE FROM users WHERE id=?;", (user_id,))
        db_close(conn, cur)
        return redirect(url_for('users'))
    except Exception as e:
        return f"An error occurred: {str(e)}"


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (user_id,))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (user_id,))
    user = cur.fetchone()

    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        about = request.form.get('about', '')
        avatar = request.files.get('avatar')

        if avatar:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET fullname=%s, email=%s, about=%s, avatar=%s WHERE id=%s;",
                            (fullname, email, about, filename, user_id))
            else:
                cur.execute("UPDATE users SET fullname=?, email=?, about=?, avatar=? WHERE id=?;",
                            (fullname, email, about, filename, user_id))
        else:
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET fullname=%s, email=%s, about=%s WHERE id=%s;",
                            (fullname, email, about, user_id))
            else:
                cur.execute("UPDATE users SET fullname=?, email=?, about=? WHERE id=?;",
                            (fullname, email, about, user_id))

        db_close(conn, cur)
        return redirect(url_for('users'))

    db_close(conn, cur)
    return render_template('edit_user.html', user=user)


@app.route('/delete_ad_admin/<int:ad_id>', methods=['POST'])
def delete_ad_admin(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Пользователь должен быть авторизован

    try:
        conn, cur = db_connect()

        # Проверяем, администратор ли пользователь
        is_admin = session.get('is_admin', False)
        
        if is_admin:
            # Администратор может удалить любое объявление
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
            else:
                cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
        else:
            # Если пользователь не администратор, проверяем, является ли он владельцем объявления
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
            else:
                cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
            ad = cur.fetchone()

            if ad and ad['user_id'] == session['user_id']:
                # Если объявление принадлежит текущему пользователю, удаляем его
                if current_app.config['DB_TYPE'] == 'postgres':
                    cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
                else:
                    cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
            else:
                # Если это не ваше объявление, перенаправляем на главную страницу
                db_close(conn, cur)
                return redirect(url_for('main'))

        db_close(conn, cur)
        return redirect(url_for('main'))  # Перенаправляем на главную страницу после удаления
    except Exception as e:
        db_close(conn, cur)
        return f"An error occurred: {str(e)}"