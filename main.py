#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import hmac

import hashlib
import random
import hmac
import re

from string import letters
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
autoescape=True)

secret = 'Zp2cA6ULKhUfZDB'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    #set coookie whose name is name and value is val
    def set_secure_cookie(self, name, val):
        #no expire time -- expries when browser closes
        cookie_val = make_secure_val(val)

        #add header to / path
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        #find cookie in the request
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    #delete the cookie when user logs out
    #user_id=; means cookie is set to nothing
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #checks whether user is logged in and checks cookie
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        
        #
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<strong>' + post.subject + '</strong><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')

## user stuff ##
def make_salt(length = 6):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest() ##possible bug
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'): #function is for organizing user groups
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =',name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(), 
                    name = name, 
                    pw_hash = pw_hash, 
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

    
#blog stuff#
#clarify purpose of function, SteHuff wasn't very clear...
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True) # StringProperty can be indexed, smaller max size
    content = db.TextProperty(required = True) # TextProperty can't be indexed, larger max size
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    created_by = db.TextProperty()
    likes = db.IntegerProperty(required=True, default=0)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        #select * from User where name == name
        u = cls.all().filter('name =', name).get()
        return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    
    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))

class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")
        
class FrontPageHandler(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created DESC limit 10")
        self.render('front.html', posts=posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.render(404)
            return
        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, 
            content = content, likes = 0,
            created_by = User.by_name(self.user.name).name, liked_by=[])
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content both required."
            self.render("newpost.html", subject = subject, content = content, error = error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.render("welcome.html", username = self.username)
            #self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

class LikeError(BlogHandler):
    def get(self):
        self.write("You can't like your own post & can only like a post once.")


class EditDeleteError(BlogHandler):
    def get(self):
        self.write('You can only edit or delete posts you have created.')


class UpdatePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name
            print "n1 = ", n1
            print "n2 = ", n2
            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                print "post = ", post
                error = ""
                self.render("newpost.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                self.redirect("/editDeleteError")

    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            
            if subject and content:
                
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                p = db.get(key)
                p.subject = self.request.get('subject')
                p.content = self.request.get('content')
            
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
                pid = p.key().id()
                print "pid = ", str(pid)
                post_user = User.by_name(self.user.name).name
                print "post created by %s" % post_user
            else:
                error = "please provide subject AND content for post"
                self.render("newpost.html", subject=subject, content=content, error = error)

class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                self.redirect('/likeError')
            else:
                post.likes = post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                #self.render('front.html', posts = posts)
                self.redirect('/blog')


class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name

            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.delete()
                self.render("deletepost.html")
            else:
                self.redirect("/editDeleteError")

class NewComment(BlogHandler):
    def get(self, post_id):
        #
        # Display the new comment page
        #
        if not self.user:
            error = "You must be logged in to comment"
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html", subject=subject, content=content, pkey=post.key())
    def post(self, post_id):
        #
        # New comment was made
        #
        # make sure post_id exists
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        # make sure user is signed in
        if not self.user:
            self.redirect('login')
        # create comment
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key())
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "please provide a comment!"
            self.render("permalink.html", post = post, content=content, error=error)

class UpdateComment(BlogHandler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id( int(post_id), parent=blog_key() )
        comment = Comment.get_by_id( int(comment_id), parent=self.user.key() )
        if comment:
            self.render("updatecomment.html", subject=post.subject, content=post.content, comment=comment.comment)
        else:
            self.redirect('/commenterror')
    def post(self, post_id, comment_id):
        comment = Comment.get_by_id( int(comment_id), parent=self.user.key() )
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect( '/blog/%s' % str(post_id) )

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id( int(post_id), parent=blog_key() )
        # this ensures the user created the comment
        comment = Comment.get_by_id( int(comment_id), parent=self.user.key() )
        if comment:
            comment.delete()
            self.redirect('/blog/%s' % str(post_id))
        else:
            self.redirect('/commenterror')

class CommentError(BlogHandler):
    def get(self):
        self.write('You can only edit or delete comments you have created.')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/welcome', Welcome),
    ('/blog', FrontPageHandler),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/([0-9]+)/newcomment', NewComment),
    ('/blog/([0-9]+)/updatecomment/([0-9]+)', UpdateComment),
    ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
    ('/commenterror', CommentError),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)/updatepost', UpdatePost),
    ('/blog/([0-9]+)/like', LikePost),
    ('/signup', Register),
    ('/blog/([0-9]+)/deletepost', DeletePost),
    ('/login', Login),
    ('/logout', Logout),
    ('/editDeleteError', EditDeleteError),
    ('/likeError', LikeError)
], debug=True)
