"""
ClawCraft Backend — Flask app with user auth, admin panel, products, and Stripe-ready payments.
"""
import os, secrets, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# ── App Setup ──
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "data", "clawcraft.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Stripe (placeholder — set these env vars when ready)
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ── Models ──
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    short_desc = db.Column(db.String(200))
    description = db.Column(db.Text)
    price_cents = db.Column(db.Integer, nullable=False)  # in cents
    price_label = db.Column(db.String(30))  # "$19", "$97", etc.
    icon = db.Column(db.String(10))
    features = db.Column(db.Text)  # JSON array
    category = db.Column(db.String(30))  # template, skills, course, session, custom
    stripe_price_id = db.Column(db.String(100))  # for Stripe integration
    is_active = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def price_dollars(self):
        return self.price_cents / 100

    @property
    def features_list(self):
        try:
            return json.loads(self.features) if self.features else []
        except:
            return []


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, refunded
    amount_cents = db.Column(db.Integer)
    stripe_session_id = db.Column(db.String(200))
    stripe_payment_intent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    product = db.relationship('Product')


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    interest = db.Column(db.String(50))
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Public Routes ──
@app.route('/')
def home():
    products = Product.query.filter_by(is_active=True).order_by(Product.sort_order).all()
    return render_template('home.html', products=products, stripe_key=STRIPE_PUBLISHABLE_KEY)


@app.route('/product/<slug>')
def product_detail(slug):
    product = Product.query.filter_by(slug=slug, is_active=True).first_or_404()
    return render_template('product.html', product=product, stripe_key=STRIPE_PUBLISHABLE_KEY)


# ── Auth Routes ──
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('signup.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('signup.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('signup.html')
        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Welcome to ClawCraft! 🦞', 'success')
        return redirect(url_for('dashboard'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# ── User Dashboard ──
@app.route('/dashboard')
@login_required
def dashboard():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('dashboard.html', orders=orders)


# ── Purchase Flow (Stripe-ready) ──
@app.route('/buy/<slug>', methods=['POST'])
@login_required
def buy_product(slug):
    product = Product.query.filter_by(slug=slug, is_active=True).first_or_404()

    # Check if already purchased
    existing = Order.query.filter_by(user_id=current_user.id, product_id=product.id, status='paid').first()
    if existing:
        flash('You already own this product!', 'info')
        return redirect(url_for('dashboard'))

    if STRIPE_SECRET_KEY:
        # TODO: Create Stripe checkout session
        # import stripe
        # stripe.api_key = STRIPE_SECRET_KEY
        # session = stripe.checkout.Session.create(...)
        # return redirect(session.url)
        pass

    # For now: create a pending order (Stripe not connected yet)
    order = Order(
        user_id=current_user.id,
        product_id=product.id,
        amount_cents=product.price_cents,
        status='pending'
    )
    db.session.add(order)
    db.session.commit()
    flash('Order created! Payment processing will be available soon. 🦞', 'info')
    return redirect(url_for('dashboard'))


# ── Stripe Webhook (placeholder) ──
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    # TODO: Verify webhook signature and process events
    # import stripe
    # event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    # if event['type'] == 'checkout.session.completed': ...
    return jsonify({'status': 'ok'}), 200


# ── Contact Form (API) ──
@app.route('/api/contact', methods=['POST'])
def contact_submit():
    data = request.get_json() or request.form
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    interest = data.get('interest', '')
    message = data.get('message', '').strip()

    if not name or not email or not message:
        return jsonify({'error': 'All fields required'}), 400

    msg = ContactMessage(name=name, email=email, interest=interest, message=message)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'status': 'ok', 'message': 'Message received! We\'ll get back to you within 24 hours.'}), 200


# ── ADMIN ROUTES ──
def admin_required(f):
    from functools import wraps
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).limit(50).all()
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).limit(50).all()
    products = Product.query.order_by(Product.sort_order).all()
    stats = {
        'total_users': User.query.count(),
        'total_orders': Order.query.count(),
        'paid_orders': Order.query.filter_by(status='paid').count(),
        'revenue_cents': db.session.query(db.func.sum(Order.amount_cents)).filter(Order.status == 'paid').scalar() or 0,
        'unread_messages': ContactMessage.query.filter_by(is_read=False).count(),
    }
    return render_template('admin.html', users=users, orders=orders, messages=messages, products=products, stats=stats)


@app.route('/admin/user/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    action = request.form.get('action')
    if action == 'toggle_admin':
        if user.id != current_user.id:
            user.is_admin = not user.is_admin
            db.session.commit()
            flash(f'{"Granted" if user.is_admin else "Revoked"} admin for {user.email}', 'success')
    elif action == 'delete':
        if user.id != current_user.id:
            db.session.delete(user)
            db.session.commit()
            flash(f'Deleted user {user.email}', 'success')
    elif action == 'grant_product':
        product_id = request.form.get('product_id')
        if product_id:
            order = Order(user_id=user.id, product_id=int(product_id), amount_cents=0, status='paid', paid_at=datetime.utcnow())
            db.session.add(order)
            db.session.commit()
            flash(f'Granted product to {user.email}', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/order/<int:order_id>', methods=['POST'])
@admin_required
def admin_edit_order(order_id):
    order = Order.query.get_or_404(order_id)
    action = request.form.get('action')
    if action == 'mark_paid':
        order.status = 'paid'
        order.paid_at = datetime.utcnow()
        db.session.commit()
        flash('Order marked as paid.', 'success')
    elif action == 'refund':
        order.status = 'refunded'
        db.session.commit()
        flash('Order marked as refunded.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/message/<int:msg_id>/read', methods=['POST'])
@admin_required
def admin_read_message(msg_id):
    msg = ContactMessage.query.get_or_404(msg_id)
    msg.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})


# ── Seed Data ──
def seed_database():
    """Create admin user and products if they don't exist."""
    # Admin account
    if not User.query.filter_by(email='admin@clawcraft.ai').first():
        admin = User(name='Tommen', email='admin@clawcraft.ai', is_admin=True)
        admin.set_password('ClawCraft2026!')
        db.session.add(admin)
        print('✅ Admin account created: admin@clawcraft.ai / ClawCraft2026!')

    # Products
    products_data = [
        {
            'slug': 'template-starter-kit',
            'name': 'Template Starter Kit',
            'short_desc': 'Go from blank config to working agent in 10 minutes.',
            'description': '''The Template Starter Kit gives you everything you need to set up a production-ready OpenClaw agent without starting from scratch.

**What's Inside:**

- **AGENTS.md Template** — Pre-configured with session startup sequences, memory management, heartbeat handling, rollcall protocols, and silent reply rules. Copy, customize, deploy.

- **SOUL.md Template** — Three persona variants (Professional Assistant, Casual Sidekick, Technical Expert) with guidance on boundaries, voice, and continuity. Pick one and make it yours.

- **HEARTBEAT.md Patterns** — 5 ready-to-use heartbeat configurations: email monitoring, calendar checker, weather briefing, security audit, and social media tracker. Each with proper scheduling and state tracking.

- **MEMORY.md Structure Guide** — How to organize long-term memory, squad management, runtime notes, and rollcall protocols. Includes real-world examples from production setups.

- **5 Cron Configurations** — Morning briefing, midday check-in, evening summary, weekly review, and custom interval templates. All tested and ready to paste into your setup.

- **USER.md & IDENTITY.md Templates** — Proper structure for tracking user preferences, timezone, context, and agent identity.

Every template comes with inline comments explaining what each section does and how to customize it. Built from real deployments running 24/7.''',
            'price_cents': 1900,
            'price_label': '$19',
            'icon': '📋',
            'features': json.dumps([
                'AGENTS.md starter template',
                'SOUL.md personality config (3 variants)',
                'HEARTBEAT.md patterns (5 configs)',
                'MEMORY.md structure guide',
                '5 ready-to-use cron configs',
                'USER.md & IDENTITY.md templates',
                'Inline documentation',
                'Instant download'
            ]),
            'category': 'template',
            'sort_order': 1
        },
        {
            'slug': 'premium-skills-pack',
            'name': 'Premium Skills Pack',
            'short_desc': 'Production-ready skills you drop straight into OpenClaw.',
            'description': '''The Premium Skills Pack is a collection of battle-tested OpenClaw skills built for real-world automation. Each skill follows the AgentSkills spec, includes full documentation, and works out of the box.

**Skills Included:**

- **📧 Email Monitor** — Connects to Gmail/IMAP, monitors inbox for important emails, summarizes new messages, and can auto-reply based on rules you define. Includes OAuth setup guide.

- **📱 Social Media Pipeline** — Complete posting pipeline for X (Twitter). Content generation via AI, image creation, scheduled posting, and engagement tracking. Includes content engine and posting scripts.

- **💰 Finance Tracker** — Monitors stock portfolios, crypto prices, and spending. Daily/weekly summary reports with alerts for significant changes. Connects to popular financial APIs.

- **🌤️ Weather & Scheduling** — Advanced weather skill with location-aware forecasts, severe weather alerts, and calendar integration. Automatically adjusts reminders based on weather conditions.

- **🔒 Security Healthcheck** — System security auditing skill. Checks SSH configs, firewall rules, package updates, open ports, and file permissions. Generates reports with severity ratings and fix recommendations.

- **📊 System Monitor** — CPU, memory, disk, and network monitoring with configurable thresholds. Sends alerts when resources are critically low. Includes historical tracking.

Each skill includes: SKILL.md documentation, all required scripts, configuration templates, and a setup guide. Tested on Linux (Ubuntu/Debian/RHEL).''',
            'price_cents': 2900,
            'price_label': '$29',
            'icon': '⚡',
            'features': json.dumps([
                'Email automation & monitoring',
                'Social media posting pipeline',
                'Finance tracking & alerts',
                'Weather & scheduling integration',
                'Security healthcheck system',
                'System resource monitor',
                'Full documentation per skill',
                'AgentSkills spec compliant'
            ]),
            'category': 'skills',
            'sort_order': 2
        },
        {
            'slug': 'mastery-course',
            'name': 'OpenClaw Mastery Course',
            'short_desc': 'Complete curriculum from zero to power user.',
            'description': '''The OpenClaw Mastery Course is a comprehensive, structured learning path that takes you from first install to running production-grade AI agents.

**Module 1: Foundation & Setup**
- Installing OpenClaw on any platform (Linux, macOS, VPS, Raspberry Pi)
- Understanding the architecture: Gateway, agents, sessions, channels
- Connecting messaging platforms (Telegram, Discord, Signal, WhatsApp)
- Configuration deep-dive: openclaw.yaml, auth profiles, model routing

**Module 2: The Agent System**
- AGENTS.md, SOUL.md, USER.md — building your agent's personality
- Memory systems: MEMORY.md, daily logs, memory search
- Session management and continuity between restarts
- Writing effective system prompts and personas

**Module 3: Skills & Automation**
- Understanding the AgentSkills spec
- Installing skills from ClawHub
- Creating custom skills from scratch
- Skill discovery, references, and script organization

**Module 4: Sub-Agents & Orchestration**
- Spawning and managing sub-agents
- Session types: run vs. persistent sessions
- Inter-agent communication and coordination
- Building agent squads with specialized roles

**Module 5: Scheduling & Monitoring**
- Cron jobs: systemEvent vs agentTurn
- Heartbeat system: periodic checks and state tracking
- Heartbeat vs Cron: when to use which
- Building monitoring dashboards

**Module 6: Browser Automation**
- xdotool and desktop containers (Podman/Docker)
- Playwright for web scraping and interaction
- Screenshot capture and visual verification
- Handling anti-bot measures

**Module 7: API Integrations & Custom Tools**
- Connecting to external APIs (Gmail, X, financial data, weather)
- Auth profile management
- Building custom tool integrations
- Rate limiting and error handling

**Module 8: Production Deployment**
- Security hardening
- Backup and disaster recovery
- Performance optimization
- Scaling to multiple agents and channels

Each module includes hands-on exercises, real configuration examples, and a project you build as you go. By the end, you'll have a fully operational multi-agent system running 24/7.

**Lifetime access. All future updates included.**''',
            'price_cents': 9700,
            'price_label': '$97',
            'icon': '🎓',
            'features': json.dumps([
                '8 comprehensive modules',
                'Setup & configuration deep-dive',
                'Skills system & automation',
                'Sub-agents & orchestration',
                'Cron scheduling & heartbeats',
                'Browser automation (xdotool, Playwright)',
                'API integrations & custom tools',
                'Production deployment guide',
                'Hands-on exercises per module',
                'Lifetime access + updates'
            ]),
            'category': 'course',
            'sort_order': 3
        },
        {
            'slug': 'setup-session',
            'name': '1-on-1 Setup Session',
            'short_desc': 'Personal video call with an OpenClaw expert.',
            'description': '''Book a 60-minute video call with an OpenClaw expert who will help you get your setup running, debug your issues, and build your first automation — live.

**What You Get:**

- **60-minute video call** via Google Meet or Zoom
- **Live screen sharing** — we work on your actual setup together
- **Troubleshooting** — if something's broken, we fix it on the call
- **Custom workflow design** — tell us what you want to automate, we'll map it out and start building
- **Session recording** — you get a full recording to reference later
- **1 week follow-up support** — message us after the call if you get stuck

**Common Session Topics:**
- Initial OpenClaw installation and configuration
- Connecting messaging platforms
- Setting up your first skills and cron jobs
- Sub-agent architecture design
- Browser automation setup (desktop containers)
- Debugging specific issues
- Migration from other AI agent platforms

**How It Works:**
1. Purchase the session
2. You'll receive a Calendly link to book your preferred time slot
3. We meet, we build, we fix things
4. You get the recording + 1 week of async support

Come with OpenClaw installed (or we'll set it up together on the call) and a list of what you want to accomplish.''',
            'price_cents': 9900,
            'price_label': '$99',
            'icon': '🎯',
            'features': json.dumps([
                '60-minute live video call',
                'Screen sharing & live coding',
                'Custom workflow design',
                'Real-time troubleshooting',
                'Session recording provided',
                '1 week follow-up support'
            ]),
            'category': 'session',
            'sort_order': 4
        },
        {
            'slug': 'custom-agent-build',
            'name': 'Custom Agent Build',
            'short_desc': 'You describe it, we build it. Fully custom.',
            'description': '''Tell us what you need automated and we'll build it. Fully custom OpenClaw agent systems, skills, and workflows — designed, built, tested, and deployed for your specific use case.

**The Process:**

**1. Discovery Call (included)**
We hop on a 30-minute call to understand your requirements: what you want automated, what systems need to connect, what your expected workflow looks like.

**2. Architecture & Proposal**
Within 48 hours, you receive a detailed proposal: what we'll build, the timeline, and the final price. No surprises.

**3. Build Phase**
We build your custom agent system. This includes:
- Custom skills tailored to your use case
- Agent personality and behavior configuration
- Integration with your existing tools and APIs
- Sub-agent orchestration (if needed)
- Scheduling and monitoring setup
- Full testing in a staging environment

**4. Deployment & Handoff**
We deploy to your server/VPS, verify everything runs correctly, and walk you through how it all works. You get full documentation.

**5. Post-Delivery Support**
30 days of support after deployment. If something breaks or needs adjustment, we fix it.

**Example Projects We've Built:**
- Social media automation pipelines (content generation → image creation → scheduling → posting → engagement)
- Email monitoring and auto-response systems
- Financial portfolio tracking with daily alerts
- Customer support bots connected to helpdesk APIs
- Content generation systems for blogs and newsletters
- Server monitoring and incident response agents
- Lead generation and CRM integration workflows
- Personal productivity agents (calendar, tasks, notes, reminders)

**Pricing starts at $299.** Final price depends on complexity. Simple single-skill builds start at $299. Multi-agent orchestration systems typically range $500-$1500.''',
            'price_cents': 29900,
            'price_label': '$299+',
            'icon': '🏗️',
            'features': json.dumps([
                'Discovery call included',
                'Custom skill development',
                'Business & content automation',
                'Sub-agent orchestration systems',
                'Full testing & documentation',
                'Deployment to your server',
                '30-day post-delivery support',
                'Satisfaction guarantee'
            ]),
            'category': 'custom',
            'sort_order': 5
        }
    ]

    for pd in products_data:
        if not Product.query.filter_by(slug=pd['slug']).first():
            p = Product(**pd)
            db.session.add(p)
            print(f'✅ Product created: {pd["name"]}')

    db.session.commit()


# ── Init ──
with app.app_context():
    os.makedirs('data', exist_ok=True)
    db.create_all()
    seed_database()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
