#!venv/bin/python

import hashlib
import base64
import time
import gpgencryption
import io
from os import unlink, path, getenv, listdir, mkdir, chmod, umask, urandom
from shutil import rmtree
from threading import Thread
from random import randint
from sys import stderr, exit
import smtplib, ssl
from email.mime.text import MIMEText

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    send_from_directory,
    send_file,
    g,
    make_response,
    abort
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_dropzone import Dropzone
from flask_babel import Babel, _, refresh
from argparse import ArgumentParser
from werkzeug.utils import secure_filename

app = Flask(__name__)
### start of config
app.config["SECRET_KEY"] = getenv("SECRET_KEY", None)
# app.jinja_env.trim_blocks = True
# app.jinja_env.lstrip_blocks = True


app.config["DROPZONE_ALLOWED_FILE_CUSTOM"] = True
app.config["DROPZONE_ALLOWED_FILE_TYPE"] = ""
app.config['DROPZONE_MAX_FILE_SIZE'] = int(getenv("DROPZONE_MAX_FILE_SIZE", "128")) # MB
app.config["DROPZONE_SERVE_LOCAL"] = True
app.config["DROPZONE_ENABLE_CSRF"] = True
app.config["DROPZONE_TIMEOUT"] = 3600000
app.config["WTF_CSRF_SSL_STRICT"] = False # Disable looking at referrer
app.config['WTF_CSRF_TIME_LIMIT'] = None # Set CSRF token validity to session-lifetime

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = 'Strict'

app.config["ORGANIZATION"] = getenv("ORGANIZATION", "Kanzlei Hubrig")
app.config["TITLE"] = "Filer"
app.config["LANGUAGES"] = ["en", "de"]


app.config["SMTPS_HOST"] = getenv("SMTPS_HOST")
app.config["SMTPS_PORT"] = int(getenv("SMTPS_PORT", "465"))
app.config["SMTPS_USER"] = getenv("SMTPS_USER")
app.config["SMTPS_PASS"] = getenv("SMTPS_PASS")
app.config["SMTPS_RECIPIENT"] = getenv("SMTPS_RECIPIENT")
enable_mail_notification = True


filettl = int(getenv("FILER_FILETTL", 10))  # file lifetime in days
support_public_docs = True
app.config["MAX_SIZE"] = "5 GB" # only an information
enable_chunking=False # enable for large files

# Enable 2FA for download?
enable_2fa = True
if enable_2fa:
    import pyotp
    import qrcode
    
# Encrypt customer-uploaded data via GPG. It is enabled if there is a
# fingerprint defined. The key is automatically downloaded from the
# keyserver. If the key cannot be downloaded, your gpg 'dirmngr' is
# likely not running, which is okay. You can import the key manually,
# just run (adjust path and file names):
# sudo -u www-data gpg --homedir /var/run/Filer/Daten/gpghome --import keyfile.asc

gpg_recipient_fprint = getenv("GPG_RECIPIENT_FPRINT", None) 
gpg_key_server = getenv("GPG_KEY_SERVER", "keys.openpgp.org")

basedir = getenv("FILER_BASEDIR", "./Daten")
publicdir = getenv("FILER_PUBLICDIR", "Public")
documentsdir = getenv("FILER_DOCUMENTSDIR", "Dokumente")
clientsdir = getenv("FILER_CLIENTSSDIR", "Mandanten")
gpg_home_dir = path.join(basedir, "gpghome")

### end of config

csrf = CSRFProtect(app)
dropzone = Dropzone(app)
babel = Babel(app)


nonce = base64.b64encode(urandom(64)).decode("utf8")
default_http_header = {
    "Content-Security-Policy": f"default-src 'self'; img-src 'self' data:; script-src 'self' 'nonce-{nonce}'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy" : "no-referrer"
}


def update_dropzone_message():
    app.config["DROPZONE_DEFAULT_MESSAGE"] = _(
        "Ziehe die Dateien hier hin, um sie hochzuladen oder klicken Sie zur Auswahl."
    )


#### ADMIN FACING DIRECTORY LISTS ####
####
####
@app.route("/admin", methods=["GET"])
def admin():

    update_dropzone_message()
    url_root = request.url_root.replace("http://", "https://", 1)

    users = []
    for f in listdir(path.join(basedir, clientsdir)):
        # filter a few technical file names
        if not f.endswith(".token") and not f.endswith(".token.disabled") and not f.endswith(".png"):
            users.append({'name': f,
                          '2fa' : user_token_enabled(f)})
            
    return (
        render_template(
            "admin.html",
            users=users,
            tree=make_tree(basedir, publicdir),
            url_root=url_root,
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
            enable_chunking=enable_chunking,
            enable_2fa=enable_2fa
        ),
        200,
        default_http_header,
    )




@app.route("/admin/" + documentsdir + "/<user>", methods=["GET"])
def admin_dokumente(user):
    user_sec = secure_filename(user)
    update_dropzone_message()
    return (
        render_template(
            "mandant.html",
            admin="admin/",
            user=user_sec,
            tree=make_tree(basedir, path.join(documentsdir, user_sec)),
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
            enable_chunking=enable_chunking,
            enable_2fa=enable_2fa and user_token_enabled("admin")
        ),
        200,
        default_http_header,
    )


@app.route("/admin/howto", methods=["GET", "POST"])
def admin_user_howto():
    user_sec = secure_filename(request.form.get("user",""))
    password = request.form.get("password")
    
    return (
        render_template(
            "howto.html",
            user=user_sec,
            password=password,
            url=request.url_root + documentsdir + "/" + user_sec,
            max_size=app.config["MAX_SIZE"],
            filettl=filettl,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
            enable_2fa=enable_2fa and user_token_enabled(user_sec)
        ),
        200,
        default_http_header,
    )

#
# API
#


@app.route("/admin/del-user/<user>", methods=["POST"])
def admin_deluser(user):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        rmtree(path.join(basedir, documentsdir, secure_filename(user)))
        unlink(path.join(basedir, clientsdir, secure_filename(user)))
        if enable_2fa:
            for suffix in [".token", ".token.disabled", ".png"]:
                try:
                    unlink(path.join(basedir, clientsdir, secure_filename(user) + suffix))
                except FileNotFoundError:
                    pass # These files may not exist.
    return redirect("/admin")


@app.route("/admin/new-user", methods=["POST"])
def admin_newuser():
    
    password = request.form.get("password", "")
    user = secure_filename(request.form.get("user", ""))
    if not password or not user:
        return "Username or password missing", 400
    
    if user == "admin":
        return abort("403")

    salt = urandom(4)
    sha = hashlib.sha1(password.encode("utf-8"))
    sha.update(salt)

    digest_salt_b64 = base64.b64encode(sha.digest() + salt)
    tagged_digest_salt = "{{SSHA}}{}".format(digest_salt_b64.decode("ascii"))

    try:
        make_dir(path.join(basedir, documentsdir, user))
        with open(
            path.join(basedir, clientsdir, user), "w+", encoding="utf-8"
        ) as htpasswd:
            htpasswd.write("{}:{}\n".format(secure_filename(user), tagged_digest_salt))

        if enable_2fa:
            create_user_token(user)
            
    except OSError as error:
        return "Couldn't create user scope", 500
    return redirect("/admin")


#### USER FACING DIRECTORY LIST ####
####
####
@app.route("/" + documentsdir + "/<user>", methods=["GET"])
def mandant(user):
    user_sec = secure_filename(user)
    update_dropzone_message()
    return (
        render_template(
            "mandant.html",
            admin="",
            user=user_sec,
            tree=make_tree(basedir, path.join(documentsdir, user_sec)),
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
            enable_chunking=enable_chunking,
            enable_2fa=enable_2fa and user_token_enabled(user_sec)
        ),
        200,
        default_http_header,
    )


#### UPLOAD FILE ROUTES ####
####
####


@app.route("/" + documentsdir + "/<user>", methods=["POST"])
def upload_mandant_as_mandant(user):
    return _upload_mandant(
        user,
        encrypt=(gpg_recipient_fprint is not None),
    )


@app.route("/admin/" + documentsdir + "/<user>", methods=["POST"])
def upload_mandant_as_admin(user):
    return _upload_mandant(user, upload_as_admin=True)


@app.route("/admin", methods=["POST"])
def upload_admin():
    return _upload_mandant(upload_as_admin=True)


def _upload_mandant(user=None, encrypt=False, upload_as_admin=False):
    
    user_sec = secure_filename(user) if user else None
    
    for key, f in request.files.items():
        if key.startswith("file"):
            filename = secure_filename(f.filename)
            if user:
                pathname = path.join(basedir, documentsdir, user_sec, filename)
            else:
                pathname = path.join(basedir, publicdir, filename)

            chunkindex = int(request.form['dzchunkindex']) if enable_chunking else 0
            chunkbyteoffset = int(request.form['dzchunkbyteoffset']) if enable_chunking else 0
            chunkcount = int(request.form['dztotalchunkcount']) if enable_chunking else 0
            
            store_file(pathname, f.stream, encrypt, chunkindex, chunkbyteoffset, chunkcount)

            if enable_mail_notification and not upload_as_admin \
               and ((chunkindex + 1 == chunkcount) or (enable_chunking is False)):
                notify_upload_via_mail(user_sec, filename)

    return make_response(("Data uploaded successfully", 200))

def store_file(pathname, fstream, encrypt, current_chunk, offset, total_chunks):

    if encrypt:
        # When uploading files in chunks, we encrypt each chunk
        # individually. Then we do not need to work with temp files,
        # and copy files here and there and to remove them afterwards.
        pathname += f".%03d.gpg" % current_chunk
        enc = gpgencryption.GPGEncryption(gpg_home_dir, gpg_key_server)
        enc.encrypt_fh(gpg_recipient_fprint, fstream, pathname)  # no signing

    else:
        with open(pathname, 'ab') as fh_out:
            fh_out.seek(offset)
            fh_out.write(fstream.read())
            
    return pathname



def notify_upload_via_mail(user, filename):

    user_sec = secure_filename(user)
    fname_sec = secure_filename(filename)
    
    context = ssl.create_default_context()
    # There is an option to disable certain TLS mechanisms, therefore we do it.
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    server = smtplib.SMTP_SSL(app.config["SMTPS_HOST"], app.config["SMTPS_PORT"], context=context)
    server.login(app.config["SMTPS_USER"], app.config["SMTPS_PASS"])

    url = request.url_root + 'admin/' + documentsdir + "/" + user_sec
    
    msg = MIMEText(f"Dear {app.config['TITLE']} user,\n\n" + \
                   f"User {user_sec} uploaded file \"{fname_sec}\". Please download it to your computer, because the\n" + \
                   f"file will be deleted on the server within {filettl} days.\n\n" + \
                   f"The file is accessible via {url}.\n\n")
    
    msg['Subject'] = f"{app.config['ORGANIZATION']} - {app.config['TITLE']}: User {user_sec} sent a file"
    msg['From'] = app.config["SMTPS_USER"]
    msg['To'] = app.config["SMTPS_RECIPIENT"]
    
    server.sendmail(app.config["SMTPS_USER"], app.config["SMTPS_RECIPIENT"], msg.as_string())


# handle CSRF error
@app.errorhandler(CSRFError)
def csrf_error(e):
    return e.description, 400

#### DELETE FILE ROUTES ####
####
####

def delete_file_mandant(user, filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(
            path.join(
                basedir, documentsdir, secure_filename(user), secure_filename(filename)
            )
        )
    return redirect("/" + documentsdir + "/" + secure_filename(user))


def delete_file_mandant_admin(user, filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(
            path.join(
                basedir, documentsdir, secure_filename(user), secure_filename(filename)
            )
        )
    return redirect("/admin/" + documentsdir + "/" + secure_filename(user))


@app.route("/admin/" + publicdir + "/<path:filename>", methods=["POST"])
def delete_file_admin(filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(path.join(basedir, publicdir, secure_filename(filename)))
    return redirect("/admin")

#### TOKEN RELATED FUNCTIONS ####
####
####

def has_token(user):
    if user == 'admin':
        path_ = path.join(basedir, "admin.token")
    else:
        path_ = path.join(basedir, clientsdir, secure_filename(user) + ".token")
    return path.exists(path_)

def user_token_enabled(user):
    if user == 'admin':
        path_ = path.join(basedir, "admin")
    else:
        path_ = path.join(basedir, clientsdir, secure_filename(user))
        
    return enable_2fa and path.exists(path_ + ".token") and \
        not path.exists(path_ + ".token.disabled")

def read_user_token(user):
    if user == 'admin':        
        token_file = path.join(basedir, "admin.token")
    else:
        token_file = path.join(basedir, clientsdir, secure_filename(user) + ".token")
        
    with open(token_file, "r", encoding="utf-8") as token_file:
        seed = token_file.readline().rstrip()
        return pyotp.TOTP(seed)

def create_user_token(user):
    if enable_2fa:

        if has_token(user):
            return
        
        if user == 'admin':
            token_file_path = path.join(basedir, "admin.token")
        else:
            token_file_path = path.join(basedir, clientsdir, secure_filename(user) + ".token")
            
        with open(token_file_path, "w+", encoding="utf-8") as token_file:
            token_file.write("{}\n".format(pyotp.random_base32()))
    
@app.route("/admin/token/toggle-state/<user>", methods=["POST"])
def admin_toggle_user_token_active(user):
    user_sec = secure_filename(user)
    path_state = path.join(basedir, clientsdir, user_sec + ".token.disabled")
    if path.exists(path_state):
        unlink(path_state)
    else:
        open(path_state, "w").close()
        
    return redirect("/admin")

@app.route("/admin/token/<user>", methods=["GET"])
def admin_download_user_token(user):
    as_attachment = False if request.args.get("inline") == 'true' else True

    user_sec = secure_filename(user)

    if not has_token(user_sec):
        create_user_token(user_sec)
        
    token = read_user_token(user_sec)
    if not token:
        return abort(500)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4)

    issuer = "{} - {}".format(app.config["ORGANIZATION"], app.config["TITLE"])
    qr.add_data(token.provisioning_uri(name=user_sec, issuer_name=issuer))
    img = qr.make_image()
    png_path = path.join(basedir, clientsdir, user_sec + ".png")
    img.save(png_path)

    return send_file(png_path,
                     as_attachment=as_attachment,
                     attachment_filename="GoogleAuth_QRToken_{}.png".format(user_sec),
                     mimetype="image/png",
                     cache_timeout=0)
    

#### SERVE FILES RULES ####
####
####


def download_file_mandant(user, filename, user_2fa, token_user=None):
    user_sec = secure_filename(user)
    user_2fa_sec = secure_filename(user_2fa)    
    if user_token_enabled(user_2fa_sec):
        token = read_user_token(user_2fa_sec)
        assert(token)
        if token is None or token.now() != token_user:
            return abort(403)
    
    return send_from_directory(
        path.join(basedir, documentsdir),
        path.join(user_sec, secure_filename(filename)),
        as_attachment = True,
        cache_timeout=0
    )


def access_resource(user, filename, user_2fa, token):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        if user_2fa == 'admin':
            return delete_file_mandant_admin(user, filename)
        else:
            return delete_file_mandant(user, filename)
    else:
        return download_file_mandant(user, filename, user_2fa, token)
    

@app.route("/admin/" + documentsdir + "/<user>/<path:filename>", methods=["GET", "POST"])
def access_resource_admin(user, filename):
    return access_resource(user, filename, 'admin', request.form.get('token'))
    
@app.route("/" + documentsdir + "/<user>/<path:filename>", methods=["GET", "POST"])
def access_resource_user(user, filename):
    return access_resource(user, filename, user, request.form.get('token'))


@app.route("/" + publicdir + "/<path:filename>")
def access_resource_public(filename):
    return send_from_directory(path.join(basedir, publicdir), filename)


def make_tree(rel, pathname, clean_expired=True):
    tree = dict(name=pathname, download=path.basename(pathname), children=[])
    try:
        lst = listdir(path.join(rel, pathname))
    except OSError:
        pass  # ignore errors
    else:
        for name in lst:
            fn = path.join(pathname, name)
            if path.isdir(path.join(rel, fn)):
                tree["children"].append(make_tree(rel, fn, clean_expired))
            else:
                ttl = filettl - int(
                    (time.time() - path.getmtime(path.join(rel, fn))) / (24 * 3600)
                )
                if clean_expired and ttl < 0:
                    unlink(path.join(rel, fn))
                else:
                    tree["children"].append(dict(name=fn, download=name, ttl=ttl))
    return tree


# Start a cleaner thread that will trigger make_tree's side effect of
# wiping old files
def cleaner_thread():
    while True:
        make_tree(basedir, documentsdir)
        # sleep for 6h plus jitter
        time.sleep(21600 + randint(1, 1800))


def make_dir(dir_name):
    if not path.exists(dir_name):
        mkdir(dir_name)
        chmod(dir_name, 0o700)


@babel.localeselector
def get_locale():
    if not g.get("lang_code", None):
        g.lang_code = request.accept_languages.best_match(app.config["LANGUAGES"])
    return g.lang_code


# Main program

umask(0o177)

thread = Thread(target=cleaner_thread, args=())
thread.daemon = True
thread.start()

# Ensure all working directories are there
try:
    for datadir in (
        basedir,
        path.join(basedir, documentsdir),
        path.join(basedir, clientsdir),
        path.join(basedir, publicdir),
    ):
        make_dir(datadir)
except:
    stderr.write("Error: Basedir not accessible\n")
    exit(1)

if app.config["SECRET_KEY"] is None:
    stderr.write("Error: Flask secret key is not set.\n")
    exit(1)

# download GPG key if enabled
if gpg_recipient_fprint is not None:
    enc = gpgencryption.GPGEncryption(gpg_home_dir, gpg_key_server)
    enc.download_key(gpg_recipient_fprint)


if __name__ == "__main__":
    parser = ArgumentParser(description="Filer")
    parser.add_argument(
        "-H",
        "--host",
        help="Hostname of the Flask app " + "[default %s]" % "127.0.0.1",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-P",
        "--port",
        help="Port for the Flask app " + "[default %s]" % "5000",
        default="5000",
    )

    args = parser.parse_args()

    app.run(host=args.host, port=int(args.port), debug=True)
