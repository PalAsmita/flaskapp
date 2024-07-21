from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy




app=Flask(__name__)
app.config['SECRET_KEY']= 'oursecretkey'
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False


db=SQLAlchemy(app)





class User(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    first_name= db.Column(db.String(150), nullable=False)
    last_name= db.Column(db.String(150), nullable=False)
    email= db.Column(db.String(150), unique=True, nullable=False)
    password= db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'






class SignUpForm(FlaskForm):
    first_name= StringField('First Name', validators=[DataRequired()])
    last_name= StringField('Last Name', validators=[DataRequired()])
    email= StringField('Email', validators=[DataRequired(), Email()])
    password= PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password= PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit= SubmitField('Sign Up')

class SignInForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')





def hash_password(password):
    """Hash a password using werkzeug's generate_password_hash."""
    return generate_password_hash(password)

def check_password(stored_password, provided_password):
    """Check if the provided password matches the stored hash."""
    return check_password_hash(stored_password, provided_password)



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already in use. Please choose a different one.', 'error')
            return redirect(url_for('sign_up'))
        
        hashed_password = hash_password(form.password.data)
        new_user = User(
            first_name=form.first_name.data, 
            last_name=form.last_name.data, 
            email=form.email.data, 
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now sign in.', 'success')
        return redirect(url_for('thank_you'))  
    return render_template('sign_up.html', form=form)



@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password(user.password, form.password.data):
            flash('Logged in', 'success')
            return redirect(url_for('secret_page'))
        else:
            flash('Check email and password.', 'error')
    return render_template('sign_in.html', form=form)



@app.route('/secret_page')
def secret_page():
    return render_template('secret_page.html')

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')




if __name__ == '__main__':
    app.run(debug=True)
