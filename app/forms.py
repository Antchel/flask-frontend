import wtforms.csrf.core
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, SelectField, validators
from wtforms.validators import DataRequired, Length, Regexp


class SignUpForm(FlaskForm):
    class Meta:
        csrf = False

    username = StringField('Username', validators=[Length(min=4, message="Too short username"),
                                                   DataRequired(message="Could not be empty"),
                                                   Regexp(r'[a-zA-Z0-9]+', message=r"Invalid username! Enter only "
                                                                                   r"possible symbols a-z, 0-9")])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     Length(min=6, max=64, message='Password length must be '
                                                                                   'between %(min)d and %(max)d characters'),
                                                     Regexp(r'[a-zA-Z0-9/+!@#$%^&*:~]+',
                                                            message="Password has immpossible symbols (Use only a-zA-Z0-9/+!@#$%^&*:~)")])
    submit = SubmitField('Sign in')


class RegisterForm(FlaskForm):
    class Meta:
        csrf = False

    username = StringField('Username', validators=[DataRequired(message="Could not be empty"),
                                                   Length(min=4, message="Too short username. Minimum 4 "
                                                                         "symbols required!"),
                                                   Regexp(r'[a-zA-Z0-9]+', message=r"Invalid username! Enter only "
                                                                                   r"possible symbols a-z, 0-9")])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Length(min=6, max=64, message='Password length must be '
                                                                       'between %(min)d and %(max)d characters'),
                                         Regexp(r'[a-zA-Z0-9/+!@#$%^&*:~]+',
                                                message="Password has immpossible symbols (Use only a-zA-Z0-9/+!@#$%^&*:~)")])
    valid_password = PasswordField('Validate Password',
                                   validators=[validators.DataRequired(),
                                               Length(min=6, max=64, message='Password length must be '
                                                                             'between %(min)d and'
                                                                             ' %(max)d characters'),
                                               Regexp(r'[a-zA-Z0-9/+!@#$%^&*:~]+',
                                                      message="Password has immpossible symbols (Use only a-zA-Z0-9/+!@#$%^&*:~)")])
    register = SubmitField('Sign up')


class CreateLinkForm(FlaskForm):
    class Meta:
        csrf = False

    source_link = StringField('Link',
                              validators=[DataRequired("Please, enter a URL"),
                                          Length(min=6, message='Real URL should be longer'),
                                          Regexp('http[s]?://(?:[a-zA-Z]|[0-9]|'
                                                 '[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                                 message= "Incorrect URL")])
    human_link = StringField('Attribute', validators=[Length(max=32, message='Please cut back your link-name')])
    link_type = SelectField('Type', choices=[('1', 'general'),
                                             ('2', 'public'),
                                             ('3', 'private')])
    submit = SubmitField('Create')


class EditLinkForm(FlaskForm):
    class Meta:
        csrf = False

    human_link = StringField('Attribute',
                             validators=[Length(max=32, message='Please cut back your link-name(Max length = 32)')])
    link_type = SelectField('Type', choices=[('1', 'general'),
                                             ('2', 'public'),
                                             ('3', 'private')])
    submit = SubmitField('Apply changes')


class AuthorizationForm(FlaskForm):
    class Meta:
        csrf = False

    username = StringField('Username',
                           validators=[DataRequired(message="Could not be empty"),
                                       Length(min=4, message="too short username! Minimum 4 symbols required!"),
                                       Regexp(r"[a-zA-Z0-9]+",
                                              message="Username has wrong symbols. Possible symbols a-z, 0-9")])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Length(min=6, max=64, message='Password length must be '
                                                                       'between %(min)d and %(max)d characters'),
                                         Regexp(r'[a-zA-Z0-9/+!@#$%^&*:~]+',
                                                message="Password has immpossible symbols (Use only a-zA-Z0-9/+!@#$%^&*:~)")])
    submit = SubmitField('Login')


class FreeLinkForm(FlaskForm):
    class Meta:
        csrf = False

    source_link = StringField('Link',
                              validators=[DataRequired("Please, enter a URL"),
                                          Length(min=6, message='Real URL should be longer'),
                                          Regexp('http[s]?://(?:[a-zA-Z]|[0-9]|'
                                                 '[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message= "Incorrect URL")])
    submit = SubmitField('Create short link')
