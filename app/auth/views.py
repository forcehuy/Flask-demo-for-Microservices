from datetime import datetime
from flask import current_app, render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid email or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        i_email = form.email.data
        i_username = form.username.data
        i_password = form.password.data
        user = User(email=i_email,
                    username=i_username,
                    password=i_password)
        db.session.add(user)
        db.session.commit()

        token = current_app.generate_confirmation_token()
        email_subject = 'Confirm Your Account [' + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ']'
        send_email(i_email, email_subject, 'auth/email/confirm', 
                user=user, token=token)
        flash('Your account have been successfully created and you can now login. '
            'Please check your email to confirm your account.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    if not current_user.confirmed:
        token = current_user.generate_confirmation_token()
        email_subject = 'Confirm Your Account [' + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ']'
        send_email(current_user.email, email_subject,
                'auth/email/confirm', user=current_user, token=token)
        flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


@auth.route('/request-password-reset', methods=['GET', 'POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = user.generate_confirmation_token()
            email_subject = 'Change Account Password [' + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ']'
            send_email(user.email, email_subject,
                       'auth/email/request-password-reset',
                       user=user, token=token)
            flash('Please click the link sent to your email to change your account password.')
            return redirect(url_for('auth.login'))
        else:
            flash('Account does not exist')
    return render_template('auth/request-password-reset.html', form=form)


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def password_reset(token=None):
    form = PasswordResetForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated() and token is not None:
            flag = User.reset_password(token=token, expiration=900, new_password=form.password.data)
            if flag:
                flash('Your password has been updated.')
                return redirect(url_for('auth.login'))
            else:
                flash('The confirmation link is invalid or have expired.')
                render_template('auth/reset-password.html', form=form, token=token)
    return render_template('auth/reset-password.html', form=form, token=token)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data.lower()
            token = current_user.generate_change_email_token(new_email)
            email_subject = 'Change Email Address [' + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ']'
            send_email(new_email, email_subject,
                       'auth/email/change-email-address',
                       user=current_user, token=token)
            flash('Please click the link sent to your current email address to verification.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change-email.html", form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash('Your email address has been updated.')
    else:
        flash('The confirmation link is invalid or have expired. Please request a new one')
    return redirect(url_for('main.index'))