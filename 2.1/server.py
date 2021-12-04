from flask import Flask, render_template, request, make_response, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from hashlib import md5, sha256
import os
import hmac

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(
    basedir, 'db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


class Session(db.Model):
    session_id = db.Column(db.String(), primary_key=True)
    user_id = db.Column(db.Integer, unique=False, nullable=False)

    def __repr__(self):
        return '<Session %r>' % self.session_id


class EncryptionManager:
    def __init__(self, aes_key, nonce):
        aes_context = Cipher(algorithms.AES(aes_key), modes.CTR(
            nonce), backend=default_backend())
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()

    def updateEncryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def finalizeEncryptor(self):
        return self.encryptor.finalize()

    def updateDecryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

    def finalizeDecryptor(self):
        return self.decryptor.finalize()


@app.route("/")
def home():
    session_id = request.cookies.get('session_id')
    if session_id:
        user_id = Session.query.get(session_id).user_id
        username = User.query.get(user_id).username
        return render_template("index.html", user=username)
    else:
        abort(401)


@app.route("/signup", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        senha = request.form["senha"]

        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8,
                     p=1, backend=default_backend())

        digest = kdf.derive(senha.encode('ascii'))

        digest_b64 = b64encode(digest).decode('ascii')
        salt_b64 = b64encode(salt).decode('ascii')

        user = User(username=username, email=email,
                    senha=(salt_b64+digest_b64))
        db.session.add(user)
        db.session.commit()

        return render_template("signup.html"), 201
    if request.method == "GET":
        return render_template("signup.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":

        # ! Retrieve base64 data from client
        session_keys_b64 = request.form['session_keys']
        ciphertext_b64 = request.form['ciphertext']
        hmac_b64 = request.form['hmac']

        #! Decode and parse session keys
        session_keys = b64decode(session_keys_b64.encode('ascii'))
        aes_key = session_keys[0:32]
        mac_key = session_keys[32:64]
        nonce = session_keys[64:80]

        # ! Decode and decrypt ciphertext
        ciphertext = b64decode(ciphertext_b64.encode('ascii'))

        manager = EncryptionManager(aes_key, nonce)

        for i in range(len(ciphertext)):
            if ciphertext[i] == 32:
                sep = i
                break

        email_encrypted = ciphertext[:sep]
        senha_encrypted = ciphertext[sep+1:]

        email_decrypted = manager.updateDecryptor(
            email_encrypted).decode('ascii')
        senha_decrypted = manager.updateDecryptor(
            senha_encrypted).decode('ascii')

        manager.finalizeDecryptor()

        # ! HMAC handling
        hmac_client = b64decode(hmac_b64.encode('ascii'))
        hmac_server = hmac.new(
            mac_key, (email_encrypted + senha_encrypted), sha256).digest()

        if hmac_client != hmac_server:
            msg = "Integridade dos dados comprometida."
            return render_template("login.html", msg=msg), 401

        user_db = User.query.filter_by(email=email_decrypted).first()
        if user_db:
            senha_db_b64 = user_db.senha
            senha_db_bytes = b64decode(senha_db_b64.encode('ascii'))
            salt = senha_db_bytes[0:16]

            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8,
                         p=1, backend=default_backend())

            digest_login = kdf.derive(senha_decrypted.encode('ascii'))
            digest_login_b64 = b64encode(digest_login).decode('ascii')
            salt_b64 = b64encode(salt).decode('ascii')

            digest_final = salt_b64 + digest_login_b64

            if digest_final == senha_db_b64:
                session_id = md5(os.urandom(16)).hexdigest()
                session = Session(session_id=session_id,
                                  user_id=user_db.id)
                db.session.add(session)
                db.session.commit()
                resp = make_response('Bolacha criada.')
                resp.set_cookie('session_id', session_id)
                return resp, 302
            else:
                msg = "Senha incorreta."
        else:
            msg = "Email não existe."

        return render_template("login.html", msg=msg), 401

    return render_template("login.html")


@ app.route("/logout", methods=["POST", "GET"])
def logout():
    if request.method == "POST":
        resp = make_response("Bolacha removida.")
        session_id = request.cookies.get('session_id')
        session = Session.query.get(session_id)
        db.session.delete(session)
        db.session.commit()
        resp.set_cookie('session_id', 'qqr', max_age=0)

        return resp, 302

    return render_template("logout.html")


if __name__ == "__main__":
    app.run(debug=True)
