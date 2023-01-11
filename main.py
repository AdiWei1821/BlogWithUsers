from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        else:
            return function(*args, **kwargs)

    return decorated_function


##CONFIGURE TABLES

class Users(UserMixin, db.Model):  # Parent
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), unique=True, nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    # Create Foreign Key to link users
    auther_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_comments = relationship("Comment", back_populates="blog_post_parent")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    blog_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    blog_post_parent = relationship("BlogPost", back_populates="blog_comments")
    comment_text = db.Column(db.Text, nullable=False)
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    commenter = relationship("Users", back_populates="comments")

# with app.app_context():
    # db.drop_all()
    # db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        with app.app_context():
            user_to_register = Users(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data,
                                                method='pbkdf2:sha256',
                                                salt_length=8)
            )
            try:
                db.session.add(user_to_register)
                db.session.commit()
                login_user(user_to_register)
                flash("You have successfully signed in!")
                return redirect(url_for('get_all_posts'))
            except IntegrityError:
                flash("You've already signed up - please login.")
                return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("That password is incorrect - please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comments = Comment.query.filter_by(blog_post_id=int(post_id))
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        with app.app_context():
            with db.session.no_autoflush:
                new_comment = Comment(
                    blog_post_parent=BlogPost.query.get(post_id),
                    comment_text=form.comment_text.data,
                    commenter=current_user
                )
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    # id = current_user.id # returns id of logged in user
    # if id == 1:
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                # author_id=current_user.id,
                author=current_user,
                title=form.title.data,
                subtitle=form.subtitle.data,
                date=date.today().strftime("%B %d, %Y"),
                body=form.body.data,
                img_url=form.img_url.data,
            )
            db.session.add(new_post)
            db.session.commit()

        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
