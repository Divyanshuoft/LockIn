from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class SignupForm(FlaskForm):
    username = StringField('Username', 
                         validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', 
                       validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', 
                           validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField('Confirm Password', 
                          validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', 
                         validators=[DataRequired()])
    password = PasswordField('Password', 
                           validators=[DataRequired()])
    submit = SubmitField('Log In')
