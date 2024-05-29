import authlib.jose.errors
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, current_app
from flask_login import UserMixin, AnonymousUserMixin
from . import db, login_manager
from authlib.jose import JsonWebSignature
import json, hashlib
from datetime import datetime
from markdown import markdown
import bleach


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default_role = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                              Permission.WRITE, Permission.MODERATE,
                              Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default_role = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm


    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

db.event.listen(Post.body, 'set', Post.on_changed_body)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            else:
                self.role = Role.query.filter_by(default_role=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.generate_gravatar_hash()
        self.follow(self)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        jws = JsonWebSignature()
        protected = {'alg': 'HS384'}
        payload = '{"confirm":' + str(self.id) + ', "timestamp":"' + str(datetime.now()) + '"}'
        secret = current_app.config['SECRET_KEY']
        token = jws.serialize_compact(protected, payload, secret)
        return token

    def confirm(self, token, expiration=3600):
        jws = JsonWebSignature()
        try:
            data = jws.deserialize_compact(token, key=current_app.config['SECRET_KEY'])
        except authlib.jose.errors.BadSignatureError:
            return False
        except:
            return False
        
        decoded_payload = json.loads(data.get('payload'))
        timestamp = datetime.strptime(decoded_payload.get('timestamp'), '%Y-%m-%d %H:%M:%S.%f')
        duration_in_second = (datetime.now() - timestamp).total_seconds()
        user_id = decoded_payload.get('confirm')
        if duration_in_second < 0 or duration_in_second > expiration or user_id != self.id:
            return False
        else:
            self.confirmed = True
            db.session.add(self)
            return True

    @staticmethod
    def reset_password(token=None, expiration=900, new_password=None):
        if token is not None and new_password is not None:
            jws = JsonWebSignature()

            try:
                data = jws.deserialize_compact(token, key=current_app.config['SECRET_KEY'])
            except:
                return False
            
            decoded_payload = json.loads(data.get('payload'))
            timestamp = datetime.strptime(decoded_payload.get('timestamp'), '%Y-%m-%d %H:%M:%S.%f')
            duration_in_second = (datetime.now() - timestamp).total_seconds()
            user_id = decoded_payload.get('confirm')
            if duration_in_second < 0 or duration_in_second > expiration:
                return False
            else:
                curr_user = User.query.get(int(user_id))
                if curr_user is not None:
                    curr_user.password =  new_password
                    db.session.add(curr_user)
                    db.session.commit()
                    return True
        else:
            return False

    def generate_change_email_token(self, new_email):
        jws = JsonWebSignature()
        protected = {'alg': 'HS384'}
        payload = '{"confirm":' + str(self.id) + ', "new_email":"' + str(new_email) + '", "timestamp":"' + str(datetime.now()) + '"}'
        secret = current_app.config['SECRET_KEY']
        token = jws.serialize_compact(protected, payload, secret)
        return token

    def change_email(self, token, expiration=3600):
        if token is not None:
            jws = JsonWebSignature()
            try:
                data = jws.deserialize_compact(token, key=current_app.config['SECRET_KEY'])
            except authlib.jose.errors.BadSignatureError:
                return False
            except:
                return False
            
            decoded_payload = json.loads(data.get('payload'))
            timestamp = datetime.strptime(decoded_payload.get('timestamp'), '%Y-%m-%d %H:%M:%S.%f')
            duration_in_second = (datetime.now() - timestamp).total_seconds()
            user_id = decoded_payload.get('confirm')
            new_email = decoded_payload.get('new_email')
            if duration_in_second < 0 or duration_in_second > expiration or user_id != self.id or new_email is None:
                return False
            elif self.query.filter_by(email=new_email) is not None:
                return False
            else:
                self.email = new_email
                db.session.add(self)
                db.session.commit()
                return True
        else:
            return False
        
    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def generate_gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://www.gravatar.com/avatar'
        if self.avatar_hash is not None:
            hash_str = self.avatar_hash
        else:
            hash_str = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        return '{url}/{hash_str}?s={size}&d={default}&r={rating}'.format(
            url=url, hash_str=hash_str, size=size, default=default, rating=rating)

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id)\
            .filter(Follow.follower_id == self.id)


    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions=None):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))