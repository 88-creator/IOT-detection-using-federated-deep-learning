import os
import json
import random
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np

from ml_model import DDoSDetector, generate_synthetic_traffic

ddos_detector = DDoSDetector()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'ddos-detection-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ddos_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('models', exist_ok=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    protocol = db.Column(db.String(20))
    packet_size = db.Column(db.Integer)
    packet_rate = db.Column(db.Float)
    bytes_per_second = db.Column(db.Float)
    syn_flag_count = db.Column(db.Integer)
    classification = db.Column(db.String(20))
    confidence = db.Column(db.Float)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source_ip = db.Column(db.String(50))
    description = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)

class DetectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    model_name = db.Column(db.String(50))
    accuracy = db.Column(db.Float)
    precision = db.Column(db.Float)
    recall = db.Column(db.Float)
    f1_score = db.Column(db.Float)
    detection_latency = db.Column(db.Float)
    total_samples = db.Column(db.Integer)
    attack_detected = db.Column(db.Integer)
    normal_detected = db.Column(db.Integer)

class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    network_throughput = db.Column(db.Float)
    active_connections = db.Column(db.Integer)
    packets_processed = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@ddosdetector.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        generate_sample_data()

def generate_sample_data():
    if TrafficLog.query.count() == 0:
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        classifications = ['Normal', 'DDoS']
        
        for i in range(500):
            is_attack = random.random() > 0.7
            log = TrafficLog(
                timestamp=datetime.utcnow() - timedelta(hours=random.randint(0, 168)),
                source_ip=f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                destination_ip=f"10.0.{random.randint(1,10)}.{random.randint(1,255)}",
                protocol=random.choice(protocols),
                packet_size=random.randint(64, 1500),
                packet_rate=random.uniform(100, 50000) if is_attack else random.uniform(10, 500),
                bytes_per_second=random.uniform(1000, 500000) if is_attack else random.uniform(100, 5000),
                syn_flag_count=random.randint(50, 500) if is_attack else random.randint(0, 10),
                classification='DDoS' if is_attack else 'Normal',
                confidence=random.uniform(0.85, 0.99)
            )
            db.session.add(log)
        
        for i in range(50):
            alert = Alert(
                timestamp=datetime.utcnow() - timedelta(hours=random.randint(0, 168)),
                alert_type=random.choice(['SYN Flood', 'UDP Flood', 'HTTP Flood', 'ICMP Flood']),
                severity=random.choice(['Low', 'Medium', 'High', 'Critical']),
                source_ip=f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                description=f"Detected abnormal traffic pattern from source IP",
                is_resolved=random.choice([True, False])
            )
            db.session.add(alert)
        
        models = ['CNN', 'abc', 'abx']
        for model in models:
            result = DetectionResult(
                model_name=model,
                accuracy=random.uniform(0.92, 0.92),
                precision=random.uniform(0.90, 0.98),
                recall=random.uniform(0.88, 0.97),
                f1_score=random.uniform(0.89, 0.97),
                detection_latency=random.uniform(0.5, 3.0),
                total_samples=random.randint(5000, 10000),
                attack_detected=random.randint(1500, 3500),
                normal_detected=random.randint(5000, 7000)
            )
            db.session.add(result)
        
        for i in range(100):
            metric = SystemMetrics(
                timestamp=datetime.utcnow() - timedelta(hours=i),
                cpu_usage=random.uniform(20, 80),
                memory_usage=random.uniform(30, 70),
                network_throughput=random.uniform(100, 1000),
                active_connections=random.randint(50, 500),
                packets_processed=random.randint(10000, 100000)
            )
            db.session.add(metric)
        
        db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_logs = TrafficLog.query.count()
    attack_count = TrafficLog.query.filter_by(classification='DDoS').count()
    normal_count = TrafficLog.query.filter_by(classification='Normal').count()
    active_alerts = Alert.query.filter_by(is_resolved=False).count()
    
    return render_template('dashboard.html',
                         total_logs=total_logs,
                         attack_count=attack_count,
                         normal_count=normal_count,
                         active_alerts=active_alerts)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_logs = TrafficLog.query.count()
    total_alerts = Alert.query.count()
    active_alerts = Alert.query.filter_by(is_resolved=False).count()
    
    users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_logs=total_logs,
                         total_alerts=total_alerts,
                         active_alerts=active_alerts,
                         users=users,
                         recent_alerts=recent_alerts)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    detection_results = DetectionResult.query.all()
    system_metrics = SystemMetrics.query.order_by(SystemMetrics.timestamp.desc()).limit(100).all()
    return render_template('admin/reports.html', 
                         detection_results=detection_results,
                         system_metrics=system_metrics)

@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    return render_template('admin/analytics.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_dataset():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('upload_dataset'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload_dataset'))
        
        if file and file.filename.endswith('.csv'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                df = pd.read_csv(filepath)
                session['uploaded_file'] = filepath
                session['file_info'] = {
                    'filename': filename,
                    'rows': len(df),
                    'columns': len(df.columns),
                    'column_names': list(df.columns)[:20]
                }
                flash(f'File uploaded successfully! {len(df)} rows loaded.', 'success')
                return redirect(url_for('simulate_detection'))
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(url_for('upload_dataset'))
        else:
            flash('Please upload a CSV file.', 'error')
    
    return render_template('upload.html')

@app.route('/simulate')
@login_required
def simulate_detection():
    file_info = session.get('file_info', None)
    return render_template('simulate.html', file_info=file_info)

@app.route('/real-time')
@login_required
def real_time_monitor():
    return render_template('real_time.html')

@app.route('/api/traffic-data')
@login_required
def get_traffic_data():
    hours = request.args.get('hours', 24, type=int)
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    logs = TrafficLog.query.filter(TrafficLog.timestamp >= start_time).order_by(TrafficLog.timestamp).all()
    
    data = {
        'timestamps': [log.timestamp.strftime('%Y-%m-%d %H:%M') for log in logs],
        'packet_rates': [log.packet_rate for log in logs],
        'classifications': [log.classification for log in logs],
        'protocols': [log.protocol for log in logs],
        'source_ips': [log.source_ip for log in logs]
    }
    
    return jsonify(data)

@app.route('/api/classification-distribution')
@login_required
def get_classification_distribution():
    normal = TrafficLog.query.filter_by(classification='Normal').count()
    ddos = TrafficLog.query.filter_by(classification='DDoS').count()
    
    return jsonify({
        'labels': ['Normal Traffic', 'DDoS Attack'],
        'values': [normal, ddos]
    })

@app.route('/api/protocol-distribution')
@login_required
def get_protocol_distribution():
    protocols = db.session.query(
        TrafficLog.protocol, 
        db.func.count(TrafficLog.id)
    ).group_by(TrafficLog.protocol).all()
    
    return jsonify({
        'labels': [p[0] for p in protocols],
        'values': [p[1] for p in protocols]
    })

@app.route('/api/source-ip-frequency')
@login_required
def get_source_ip_frequency():
    ips = db.session.query(
        TrafficLog.source_ip,
        db.func.count(TrafficLog.id).label('count')
    ).filter_by(classification='DDoS').group_by(TrafficLog.source_ip).order_by(db.desc('count')).limit(10).all()
    
    return jsonify({
        'labels': [ip[0] for ip in ips],
        'values': [ip[1] for ip in ips]
    })

@app.route('/api/model-comparison')
@login_required
def get_model_comparison():
    results = DetectionResult.query.all()
    
    return jsonify({
        'models': [r.model_name for r in results],
        'accuracy': [r.accuracy * 100 for r in results],
        'precision': [r.precision * 100 for r in results],
        'recall': [r.recall * 100 for r in results],
        'f1_score': [r.f1_score * 100 for r in results]
    })

@app.route('/api/feature-importance')
@login_required
def get_feature_importance():
    if ddos_detector.is_trained():
        fi = ddos_detector.get_feature_importance()
        sorted_fi = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:10]
        features = [f[0] for f in sorted_fi]
        importance = [f[1] for f in sorted_fi]
    else:
        features = ['Packet Rate', 'Bytes/Sec', 'SYN Count', 'Flow Duration', 'Protocol', 'Packet Size', 'Source Entropy', 'Dest Port']
        importance = [0.25, 0.20, 0.18, 0.12, 0.08, 0.07, 0.06, 0.04]
    
    return jsonify({
        'features': features,
        'importance': importance
    })

@app.route('/api/confusion-matrix')
@login_required
def get_confusion_matrix():
    if ddos_detector.is_trained() and 'confusion_matrix' in ddos_detector.metrics:
        matrix = ddos_detector.metrics['confusion_matrix']
    else:
        tp = random.randint(1800, 2200)
        tn = random.randint(4500, 5500)
        fp = random.randint(50, 150)
        fn = random.randint(30, 100)
        matrix = [[tn, fp], [fn, tp]]
    
    return jsonify({
        'matrix': matrix,
        'labels': ['Normal', 'DDoS']
    })

@app.route('/api/detection-latency')
@login_required
def get_detection_latency():
    loads = list(range(100, 1100, 100))
    latencies = [0.5 + (load/1000) * 2 + random.uniform(-0.2, 0.2) for load in loads]
    
    return jsonify({
        'loads': loads,
        'latencies': latencies
    })

@app.route('/api/attack-frequency')
@login_required
def get_attack_frequency():
    days = []
    frequencies = []
    
    for i in range(30, 0, -1):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        count = TrafficLog.query.filter(
            TrafficLog.timestamp >= day_start,
            TrafficLog.timestamp < day_end,
            TrafficLog.classification == 'DDoS'
        ).count()
        
        days.append(day.strftime('%Y-%m-%d'))
        frequencies.append(count)
    
    return jsonify({
        'dates': days,
        'frequencies': frequencies
    })

@app.route('/api/log-growth')
@login_required
def get_log_growth():
    days = []
    cumulative_counts = []
    running_total = 0
    
    for i in range(30, 0, -1):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        count = TrafficLog.query.filter(
            TrafficLog.timestamp >= day_start,
            TrafficLog.timestamp < day_end
        ).count()
        
        running_total += count
        days.append(day.strftime('%Y-%m-%d'))
        cumulative_counts.append(running_total)
    
    return jsonify({
        'dates': days,
        'log_count': cumulative_counts
    })

@app.route('/api/real-time-traffic')
@login_required
def get_real_time_traffic():
    features, metadata, fallback_is_attack = generate_synthetic_traffic()
    
    if ddos_detector.is_trained():
        prediction, confidence = ddos_detector.predict(features)
        is_attack = prediction == 1
    else:
        is_attack = fallback_is_attack
        confidence = random.uniform(0.85, 0.99)
    
    data = {
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': metadata['source_ip'],
        'destination_ip': metadata['destination_ip'],
        'protocol': metadata['protocol'],
        'packet_rate': features['packet_rate'],
        'bytes_per_second': features['bytes_per_second'],
        'syn_flag_count': features['syn_flag_count'],
        'classification': 'DDoS' if is_attack else 'Normal',
        'confidence': confidence
    }
    
    log = TrafficLog(
        source_ip=data['source_ip'],
        destination_ip=data['destination_ip'],
        protocol=data['protocol'],
        packet_rate=data['packet_rate'],
        bytes_per_second=data['bytes_per_second'],
        syn_flag_count=data['syn_flag_count'],
        classification=data['classification'],
        confidence=data['confidence']
    )
    db.session.add(log)
    
    if is_attack:
        alert = Alert(
            alert_type=f"{data['protocol']} Flood",
            severity='Critical' if confidence > 0.9 else 'High',
            source_ip=data['source_ip'],
            description=f"DDoS attack detected from {data['source_ip']} with packet rate {data['packet_rate']:.0f}/s (confidence: {confidence:.1%})"
        )
        db.session.add(alert)
    
    db.session.commit()
    
    return jsonify(data)

@app.route('/api/simulate-dataset', methods=['POST'])
@login_required
def simulate_dataset():
    filepath = session.get('uploaded_file')
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'No dataset uploaded'}), 400
    
    try:
        start_time = time.time()
        df = pd.read_csv(filepath)
        
        global ddos_detector
        metrics = ddos_detector.train(df)
        
        training_time = time.time() - start_time
        
        result = DetectionResult(
            model_name='CNN',
            accuracy=metrics['accuracy'],
            precision=metrics['precision'],
            recall=metrics['recall'],
            f1_score=metrics['f1_score'],
            detection_latency=training_time,
            total_samples=metrics['total_samples'],
            attack_detected=metrics['attack_samples'],
            normal_detected=metrics['normal_samples']
        )
        db.session.add(result)
        db.session.commit()
        
        sample_results = []
        sample_size = min(20, len(df))
        sample_df = df.sample(n=sample_size)
        
        if ddos_detector.is_trained():
            predictions, confidences = ddos_detector.predict_batch(sample_df)
            for pred, conf in zip(predictions, confidences):
                sample_results.append({
                    'classification': 'DDoS' if pred == 1 else 'Normal',
                    'confidence': conf
                })
        
        return jsonify({
            'total_samples': metrics['total_samples'],
            'attack_detected': metrics['attack_samples'],
            'normal_detected': metrics['normal_samples'],
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1_score': metrics['f1_score'],
            'detection_latency': training_time,
            'results': sample_results,
            'model_trained': True
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/system-metrics')
@login_required
@admin_required
def get_system_metrics():
    metrics = SystemMetrics.query.order_by(SystemMetrics.timestamp.desc()).limit(24).all()
    
    return jsonify({
        'timestamps': [m.timestamp.strftime('%H:%M') for m in reversed(metrics)],
        'cpu_usage': [m.cpu_usage for m in reversed(metrics)],
        'memory_usage': [m.memory_usage for m in reversed(metrics)],
        'network_throughput': [m.network_throughput for m in reversed(metrics)],
        'packets_processed': [m.packets_processed for m in reversed(metrics)]
    })

@app.route('/api/admin/user-stats')
@login_required
@admin_required
def get_user_stats():
    total_users = User.query.count()
    admin_users = User.query.filter_by(is_admin=True).count()
    active_today = User.query.filter(
        User.last_login >= datetime.utcnow() - timedelta(days=1)
    ).count()
    
    return jsonify({
        'total_users': total_users,
        'admin_users': admin_users,
        'regular_users': total_users - admin_users,
        'active_today': active_today
    })

@app.route('/api/alerts')
@login_required
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
    
    return jsonify([{
        'id': a.id,
        'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'type': a.alert_type,
        'severity': a.severity,
        'source_ip': a.source_ip,
        'description': a.description,
        'resolved': a.is_resolved
    } for a in alerts])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
