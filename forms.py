from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from models import User

class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """Form for user registration"""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Validate that username is unique"""
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('This username is already taken. Please use a different one.')

    def validate_email(self, email):
        """Validate that email is unique"""
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('This email is already registered. Please use a different one.')

class ChangePasswordForm(FlaskForm):
    """Form for changing password"""
    old_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        'Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ProfileForm(FlaskForm):
    """Form for editing user profile"""
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

class AddressForm(FlaskForm):
    """Form for adding/editing addresses"""
    address_type = SelectField('Address Type', choices=[
        ('home', 'Home'), 
        ('work', 'Work'), 
        ('billing', 'Billing'), 
        ('shipping', 'Shipping'),
        ('other', 'Other')
    ])
    street = StringField('Street Address', validators=[DataRequired(), Length(max=128)])
    city = StringField('City', validators=[DataRequired(), Length(max=64)])
    state = StringField('State/Province', validators=[Length(max=64)])
    postal_code = StringField('Postal/ZIP Code', validators=[DataRequired(), Length(max=20)])
    country = StringField('Country', validators=[DataRequired(), Length(max=64)])
    is_default = BooleanField('Set as Default Address')
    submit = SubmitField('Save Address')

class ContactForm(FlaskForm):
    """Form for adding/editing contact information"""
    contact_type = SelectField('Contact Type', choices=[
        ('home', 'Home'), 
        ('work', 'Work'), 
        ('mobile', 'Mobile'),
        ('other', 'Other')
    ])
    phone_number = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=120)])
    is_default = BooleanField('Set as Default Contact')
    submit = SubmitField('Save Contact')

class ResetPasswordRequestForm(FlaskForm):
    """Form for requesting password reset"""
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    """Form for resetting password"""
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')