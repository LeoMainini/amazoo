import os
import flask
import stripe
from flask import Flask, redirect, render_template, url_for, request, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from wtforms import StringField, SubmitField, EmailField
from wtforms.fields.numeric import FloatField
from wtforms.fields.simple import PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_required, login_user, logout_user, LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin


# TODO: Functionality
#   Add many-one rel products-seller


app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///store2.db"
lm = LoginManager(app)
Bootstrap(app)
db = SQLAlchemy(app)

print(os.environ.get("STRIPE_KEY"))
stripe.api_key = os.environ.get("STRIPE_KEY")


class Customer(db.Model, UserMixin):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    adress = db.Column(db.String(250), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    orders = relationship('Order')


products = db.Table('products',
                    db.Column('product_id', db.Integer, db.ForeignKey(
                        'product.id'), primary_key=True),
                    db.Column('order_id', db.Integer, db.ForeignKey(
                        'order.id'), primary_key=True)
                    )


class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    img_url = db.Column(db.String(500), nullable=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    description = db.Column(db.String(500), nullable=True)
    price = db.Column(db.Integer, nullable=False)


class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    bought = db.Column(db.Boolean, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    customer = relationship('Customer', back_populates="orders")
    products = relationship('Product', secondary=products, lazy='subquery',
                            backref=db.backref('orders', lazy=True))


class RegisterForm(FlaskForm):
    name = StringField('Name:', validators=[DataRequired(), Length(max=250)])
    email = EmailField('Email:', validators=[
                       DataRequired(), Length(max=250), Email()])
    password = PasswordField('Password:', validators=[
                             DataRequired(), Length(max=50, min=6)])
    adress = StringField('Adress:', validators=[
                         DataRequired(), Length(max=250)])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField('Email:', validators=[
                       DataRequired(), Length(max=250), Email()])
    password = PasswordField('Password:', validators=[
                             DataRequired(), Length(max=50, min=6)])
    submit = SubmitField("Login")


class ProductForm(FlaskForm):
    name = StringField('Name:', validators=[DataRequired(), Length(max=250)])
    img_url = StringField('Image URL:', validators=[
                          DataRequired(), Length(max=250)])
    price = FloatField('Price:', validators=[DataRequired()])
    description = TextAreaField('Description:', validators=[
                                DataRequired(), Length(max=500)])
    submit = SubmitField("Add")


class MakeSellerForm(FlaskForm):
    key = StringField("Key:", validators=[DataRequired()])
    submit = SubmitField("Submit")


db.create_all()


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


def check_existing_user(email):
    user = db.session.query(Customer).filter_by(email=email).first()
    if user:
        return True
    return False


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = db.session.query(Customer).get(current_user.id)
        if user:
            if not user.admin:
                flash('Page locked, login as admin.')
                logout_user()
                return redirect(url_for('login'))
            else:
                return function(*args, **kwargs)
        else:
            flash('Not logged in.')
            return redirect(url_for('login'))
    return wrapper


@lm.user_loader
def load_user(user_id):
    return db.session.query(Customer).get(user_id)


@app.route("/")
def home():
    products = db.session.query(Product).all()
    print(len(products))
    return render_template('home.htm', product_list=products)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        pw_hash = generate_password_hash(
            method='pbkdf2:sha256:80000', password=form.password.data)
        new_user = Customer(
            name=form.name.data,
            email=form.email.data,
            password=pw_hash,
            adress=form.adress.data,
            admin=False
        )
        next = request.args.get('next')
        if not is_safe_url(next):
            return abort(400)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    else:
        return render_template('register.htm', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(Customer).filter_by(
            email=form.email.data).first()
        if user:
            if check_password_hash(password=form.password.data, pwhash=user.password):
                next = request.args.get('next')
                if not is_safe_url(next):
                    return abort(400)
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Password doesnt match")
                return redirect(url_for('login'))
        else:
            flash("Email not registered.")
            return redirect(url_for('login'))
    return render_template('login.htm', form=form)


@app.route("/add-product", methods=["GET", "POST"])
@login_required
@admin_only
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(img_url=form.img_url.data,
                          name=form.name.data,
                          description=form.description.data,
                          price=form.price.data)
        db.session.add(product)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("add-product.htm", form=form)


@app.route("/make-seller", methods=["GET", "POST"])
@login_required
def make_admin():
    form = MakeSellerForm()
    if form.validate_on_submit():
        if form.key.data == app.secret_key:
            user = db.session.query(Customer).get(current_user.id)
            user.admin = True
            db.session.commit()
            return redirect(url_for('home'))
        else:
            return abort(401)
    return render_template('make-seller.htm', form=form)


@app.route('/cart/add/<int:id>')
@login_required
def add_cart(id):
    product = db.session.query(Product).get(id)
    user_orders = db.session.query(Customer).get(current_user.id).orders
    cart = [order for order in user_orders if order.bought == False]
    if not cart:
        new_order = Order(
            bought=False,
            customer_id=current_user.id
        )
        new_order.products.append(product)
    else:
        order = db.session.query(Order).get(cart[0].id)
        order.products.append(product)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/cart', methods=["POST", "GET"])
@login_required
def cart():
    user_orders = db.session.query(Customer).get(current_user.id).orders
    cart = [order for order in user_orders if order.bought == False]
    if cart:
        sum = 0
        for item in cart[0].products:
            sum += item.price
        return render_template('cart.htm', cart=cart[0], sum=sum)
    else:
        return render_template('cart.htm', cart=[])


@app.route("/search", methods=["POST"])
def search():
    if 'search' in request.form.keys():
        search = request.form.to_dict()['search']
        if search:
            items = Product.query.filter(func.lower(
                Product.name).contains(func.lower(search))).all()
            return render_template('search.htm', items=items, term=search)
        return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route("/payment-confirmed")
@login_required
def sucess():
    flash("Payment confirmed.")
    return render_template("post-sale.htm")


@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    user_orders = current_user.orders
    order = [order for order in user_orders if not order.bought][0]
    try:
        session = stripe.checkout.Session.create(
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': product.name,
                    },
                    'unit_amount': int(product.price * 100),
                },
                'quantity': 1,
            }for product in order.products],
            mode='payment',
            success_url=f"{request.url_root[:-1]}{url_for('sucess')}",
            cancel_url=f"{request.url_root[:-1]}{url_for('home')}",
        )

    except stripe.error.CardError as e:
        flash("Payment declined, try again or try a different payment method.")
    except stripe.error.RateLimitError as e:
        flash("Something went wrong, contact support with code #RATIO")
    except stripe.error.InvalidRequestError as e:
        flash("Something went wrong, contact support with code #STOOPID")
        pass
    except stripe.error.AuthenticationError as e:
        flash("Something went wrong, contact support with code #CHANGE")
    except stripe.error.APIConnectionError as e:
        flash("Something went wrong with the payment processor, it may be down, try again later.")
    except stripe.error.StripeError as e:
        flash("Something went wrong, try again later.")
    else:
        bought_order = db.session.query(Order).get(order.id)
        print(f"id={bought_order.id}")
        bought_order.bought = True
        db.session.commit()
    finally:
        return redirect(session.url, code=303)


if __name__ == "__main__":
    app.run(debug=True)
