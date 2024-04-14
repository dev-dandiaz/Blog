from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, URL, Email
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[InputRequired()])
    subtitle = StringField("Subtitle", validators=[InputRequired()])
    img_url = StringField("Blog Image URL", validators=[InputRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[InputRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    name = StringField("Name", validators=[InputRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Let Me In!")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[InputRequired()])
    submit = SubmitField("Submit  Comment")
