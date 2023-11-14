from flask import Flask, render_template, request, jsonify, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
import string, random, qrcode, io, os
from base64 import b64encode
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_swagger_ui import get_swaggerui_blueprint

#Get the current working directory
cwd = os.getcwd()
#the database file name
db_file = 'myDB.db'
#the absolute path to the database file
absolute_db_path = os.path.join(cwd, db_file)

# set the flask app
app = Flask(__name__)

# make the swagger configurations
SWAGGER_URL="/swagger"
API_URL="/static/swagger.json"

swagger_ui_blueprint = get_swaggerui_blueprint(
   SWAGGER_URL,
   API_URL,
    config={
        'app_name': 'URL Shortener'
    }
)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)




# Set the SQLAlchemy database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + absolute_db_path
# cretae the db
db = SQLAlchemy(app)
# setting the secret key for CSRF
app.secret_key = os.environ.get("MY_SECRET_KEY")
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/Login'


class User(db.Model, UserMixin):
    """Creating the User class"""
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)

class SignUp_Form(FlaskForm):
    """Creating the Signup form"""
    username = StringField(validators=[InputRequired(), Length(min=4, max=25)], render_kw={'placeholder':'Username',"class": "input_field"})
    password = PasswordField(validators=[InputRequired(), Length(min=5, max=20)], render_kw={'placeholder': 'Password', "class":"input_field"})
    submit = SubmitField("Sign Up", render_kw={'class':'button'})


    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("User already Exists. Please Choose a different name.")

class LogIn_Form(FlaskForm):
    """Creating the Login form"""
    username = StringField(validators=[InputRequired(), Length(min=4, max=25)], render_kw={'placeholder':'Username',"class": "input_field"})
    password = PasswordField(validators=[InputRequired(), Length(min=5, max=20)], render_kw={'placeholder': 'Password', "class":"input_field"})
    submit = SubmitField("Log In", render_kw={'class':'button'})



class Data(db.Model):
    """ Represents url data entries in the database."""
    id = db.Column("ID", db.Integer(), primary_key=True, nullable=False)
    long_url = db.Column("Long URL", db.String(), nullable=False)
    short_url = db.Column("Short URL", db.String(), nullable=False)
    QR_Code = db.Column("QR Code", db.LargeBinary, nullable=False)

    def __init__(self, long_url, short_url, QR_Code):
        self.long_url = long_url
        self.short_url = short_url
        self.QR_Code = QR_Code


def random_short_url():
    """Generating random alphabets"""
    alphabets =string.ascii_letters
    while True:
        random_letters = [random.choice(alphabets) for i in range(3)]
        random_letters = "".join(random_letters)
        short_URL = Data.query.filter_by(short_url=random_letters).first()
        if not short_URL:
            return random_letters


initialized = False
@app.before_request
def before_request():
    global initialized
    if not initialized:
        db.create_all()
        initialized = True

@login_required
@app.route("/index", methods=['POST', 'GET'])
def index_page():
    if request.method == 'POST':
            input_link = request.form.get('input_link')
            custom_words = request.form.get('customize_link')

            # Validating input_link and short_url
            if not input_link:
                return jsonify({'error': 'Input URL is required.'})
            if custom_words:
                short_url = custom_words
            else:
                short_url = random_short_url()


            # Generate QR code as image
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(input_link)
            qr.make(fit=True)
            qr_code_image = qr.make_image(fill_color="black", back_color="white")
            qr_code_bytes_io = io.BytesIO()
            qr_code_image.save(qr_code_bytes_io)
            qr_code_bytes = qr_code_bytes_io.getvalue()

            # Check if the URL already exists in the database
            existing_url = Data.query.filter_by(long_url=input_link).first()

            if existing_url:
                return render_template("shorten_url.html", short_url=short_url, long_url=existing_url.long_url)
            else:
                # Shorten the URL and store it in the database
                new_created_url = Data(long_url=input_link, short_url=short_url, QR_Code=qr_code_bytes)
                db.session.add(new_created_url)
                db.session.commit()
                return render_template("shorten_url.html", short_url=custom_words, long_url=new_created_url.long_url)
    # If the request method is GET, render the index.html template
    return render_template("index.html")

@app.route("/shorten_url")
def shorten_url():
    return render_template("index.html")
@app.route("/qr_code", methods=['POST', 'GET'])
def qr_code_page():
    if request.method == 'POST':
        input_link = request.form.get('provided_link')
        existing_qr = Data.query.filter_by(long_url=input_link).first()
        if existing_qr:
            my_qr_code = existing_qr.QR_Code
            base64_img = "data:image/png;base64," + b64encode(my_qr_code).decode('ascii')
            return render_template("qr_code.html", qr_code_image=base64_img)
        else:
            error_message = "QR Code not found for the provided link."
            return render_template("qr_code.html", error_message=error_message)

    return render_template("qr_code.html")


@app.route("/")
def home_page():
    return render_template("home.html")



@app.route("/SignUp",  methods=['GET', 'POST'])
def signup_page():
    signup_form = SignUp_Form()
    if signup_form.validate_on_submit():
        # Extract data from the form fields
        username = signup_form.username.data
        password = signup_form.password.data
        # Hash the password before storing it in the database
        hash_password = bcrypt.generate_password_hash(password)
        # Create a new user object with the extracted and hashed data
        new_user = User(username=username, password=hash_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index_page'))
        except Exception as e:
            db.session.rollback()
            print(f"Error: {str(e)}")
    return render_template("SignUp.html", form=signup_form)



@app.route("/Login", methods=['GET', 'POST'])
def signin_page():
    # Create an instance of the LogIn_Form class
    login_form = LogIn_Form()
    # Check if the form has been submitted and is valid
    if login_form.validate_on_submit():
        # Extract data from the form fields
        name = login_form.username.data
        key = login_form.password.data
        user = User.query.filter_by(username=name).first()

        # Check if a user with the given username exists
        if user:
            if bcrypt.check_password_hash(user.password, key):
                # If the password is correct, log in the user
                login_user(user)
                return redirect(url_for("index_page"))
        else:
            flash("Incorrect Password.")

    # Render the Login.html template with the login form
    return render_template("Login.html", form=login_form)
@app.route("/LogOut")
def log_out():
    logout_user()
    return redirect(url_for("home_page"))
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))






# for deleting the record from database
# @app.route("/api/delete_url/<int:url_id>", methods=['DELETE'])
# def delete_url(url_id):
#     url = Data.query.get(url_id)
#     if url:
#         db.session.delete(url)
#         db.session.commit()
#         response = {
#             'status': 'success',
#             'message': 'URL deleted successfully.'
#         }
#         return jsonify(response), 200
#     else:
#         response = {
#             'status': 'failure',
#             'message': 'URL not found.'
#         }
#         return jsonify(response), 404


if __name__ == "__main__":
    app.run(debug=False)
