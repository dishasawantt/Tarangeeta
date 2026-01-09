import re
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_ckeditor import CKEditorField
from wtforms import StringField, SubmitField, PasswordField, SelectField, TextAreaField
from wtforms.validators import DataRequired, URL, Optional, Email, ValidationError

ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mov', 'avi', 'webm', 'mkv']

def validate_email_domain(form, field):
    if not re.match(r'^[^@]+@[^@]+\.[a-zA-Z]{2,}$', field.data):
        raise ValidationError("Enter a valid email address.")


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    category = SelectField("Category", coerce=int, validators=[DataRequired()])
    media_url = StringField("Media URL", validators=[Optional(), URL()])
    media_upload = FileField("Upload Media", validators=[FileAllowed(ALLOWED_EXTENSIONS)])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), validate_email_domain])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), validate_email_domain])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


class CommentForm(FlaskForm):
    comment_text = TextAreaField("", validators=[DataRequired()])
    submit = SubmitField("Post Comment")


class SearchForm(FlaskForm):
    query = StringField("Search", validators=[DataRequired()])
    submit = SubmitField("Search")


class ContactForm(FlaskForm):
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send Message")
