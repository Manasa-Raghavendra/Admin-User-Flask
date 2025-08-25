from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email
import re

from models import db, User, Message

app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://admin_user_k0tq_user:Xv8LjwMhYqDBsvffpnmFhRtFccnUSQ1s@dpg-d2ma0lumcj7s73d503hg-a.oregon-postgres.render.com/admin_user_k0tq"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=1, max=50)])
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=4)])
    admin_code = StringField("Admin Code (optional)")
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class MessageForm(FlaskForm):
    content = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")

class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=1, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Update Profile")

@app.route("/")
def home():
    role = session.get("role")
    return render_template("home.html", role=role)



@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        admin_code_input = form.admin_code.data

        # Username validation (letters only)
        if not re.match(r"^[A-Za-z]+$", username):
            flash("Invalid username. Only alphabets allowed.", "error")
            return redirect(url_for("register"))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for("register"))
        else:
            # Set session flag to show success below input
            session['username_ok'] = True

        # Hash password
        password_hash = generate_password_hash(password)

        # Determine role
        role = "admin" if admin_code_input == "SECRET123" else "user"

        # Save user
        try:
            new_user = User(username=username, email=email, password_hash=password_hash, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            # Remove the session flag after successful registration
            session.pop('username_ok', None)
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists. Try another.", "error")
            return redirect(url_for("register"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {str(e)}", "error")
            return redirect(url_for("register"))

    return render_template("register.html", form=form)




@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session["user_id"] = user.id
                session["role"] = user.role
                flash("Login successful!", "success")
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("user_dashboard"))
            else:
                flash("Invalid username or password", "danger")
                return redirect(url_for("login"))
        except Exception:
            flash("Error logging in.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route("/user_dashboard", methods=["GET", "POST"])
def user_dashboard():
    if "user_id" not in session or session.get("role") != "user":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    form = MessageForm()
    if form.validate_on_submit():
        try:
            new_msg = Message(user_id=session["user_id"], content=form.content.data)
            db.session.add(new_msg)
            db.session.commit()
            flash("Message sent successfully!", "success")
        except Exception:
            db.session.rollback()
            flash("Error while sending message.", "danger")

    user_messages = Message.query.filter_by(user_id=session["user_id"]).all()
    return render_template("user_dashboard.html", form=form, messages=user_messages)


@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    try:
        messages = Message.query.all()
        return render_template("admin_dashboard.html", messages=messages)
    except Exception:
        flash("Error loading messages.", "danger")
        return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        new_username = form.username.data
        new_email = form.email.data

        if not re.match(r"^[A-Za-z]+$", new_username):
            flash("Invalid username. Only letters allowed.", "danger")
            return redirect(url_for("profile"))

        user.username = new_username
        user.email = new_email
        try:
            db.session.commit()
            flash("Profile updated successfully!", "success")
        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "warning")

    return render_template("profile.html", form=form)

@app.route("/resolve/<int:message_id>", methods=["POST"])
def resolve_message(message_id):
    if "user_id" not in session or session.get("role") != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    try:
        msg = Message.query.get(message_id)
        if msg:
            msg.status = "Resolved"
            db.session.commit()
            flash("Message marked as resolved!", "success")
        else:
            flash("Message not found.", "warning")
    except Exception:
        db.session.rollback()
        flash("Error updating message.", "danger")

    return redirect(url_for("admin_dashboard"))



@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
