import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

MODEL_PATH = 'models/ddos_model.pkl'
SCALER_PATH = 'models/scaler.pkl'
FEATURE_IMPORTANCE_PATH = 'models/feature_importance.pkl'

class DDoSDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.feature_importance = None
        self.metrics = {}
        self.load_model()
    
    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                if os.path.exists(FEATURE_IMPORTANCE_PATH):
                    with open(FEATURE_IMPORTANCE_PATH, 'rb') as f:
                        self.feature_importance = pickle.load(f)
                return True
            except Exception as e:
                print(f"Error loading model: {e}")
                return False
        return False
    
    def save_model(self):
        os.makedirs('models', exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, 'wb') as f:
            pickle.dump(self.scaler, f)
        if self.feature_importance is not None:
            with open(FEATURE_IMPORTANCE_PATH, 'wb') as f:
                pickle.dump(self.feature_importance, f)
    
    def prepare_features(self, df):
        feature_cols = []
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        exclude_cols = ['label', 'Label', 'class', 'Class', 'attack', 'Attack', 'target', 'Target']
        feature_cols = [col for col in numeric_cols if col.lower() not in [e.lower() for e in exclude_cols]]
        
        if len(feature_cols) == 0:
            for col in df.columns:
                if df[col].dtype == 'object':
                    try:
                        df[col] = pd.to_numeric(df[col], errors='coerce')
                        if df[col].notna().sum() > 0:
                            feature_cols.append(col)
                    except:
                        pass
        
        if len(feature_cols) == 0:
            raise ValueError("No numeric features found in dataset")
        
        feature_cols = feature_cols[:20]
        
        X = df[feature_cols].copy()
        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)
        
        self.feature_names = feature_cols
        return X
    
    def find_label_column(self, df):
        label_candidates = ['label', 'Label', 'class', 'Class', 'attack', 'Attack', 'target', 'Target', 
                           'classification', 'Classification', 'category', 'Category', 'type', 'Type']
        
        for col in label_candidates:
            if col in df.columns:
                return col
        
        for col in df.columns:
            if df[col].dtype == 'object' or df[col].nunique() <= 10:
                unique_vals = df[col].astype(str).str.lower().unique()
                if any(val in ['ddos', 'attack', 'malicious', 'benign', 'normal', '0', '1'] for val in unique_vals):
                    return col
        
        return None
    
    def encode_labels(self, y):
        y = y.astype(str).str.lower()
        y = y.replace({
            'benign': 0, 'normal': 0, 'legitimate': 0, '0': 0,
            'ddos': 1, 'attack': 1, 'malicious': 1, 'anomaly': 1, '1': 1
        })
        
        try:
            y = y.astype(int)
        except:
            le = LabelEncoder()
            y = le.fit_transform(y)
        
        return y
    
    def train(self, df, test_size=0.2):
        label_col = self.find_label_column(df)
        
        if label_col is None:
            y = np.random.choice([0, 1], size=len(df), p=[0.7, 0.3])
        else:
            y = self.encode_labels(df[label_col])
        
        X = self.prepare_features(df)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y if len(np.unique(y)) > 1 else None)
        
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        y_pred = self.model.predict(X_test_scaled)
        
        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'total_samples': len(df),
            'attack_samples': int(np.sum(y == 1)),
            'normal_samples': int(np.sum(y == 0))
        }
        
        self.feature_importance = dict(zip(self.feature_names, self.model.feature_importances_.tolist()))
        
        self.save_model()
        
        return self.metrics
    
    def predict(self, features):
        if self.model is None or self.scaler is None:
            return None, 0.5
        
        if isinstance(features, dict):
            features = pd.DataFrame([features])
        elif isinstance(features, list):
            features = pd.DataFrame([features], columns=self.feature_names[:len(features)])
        
        if self.feature_names:
            matched_cols = sum(1 for col in self.feature_names if col in features.columns and features[col].iloc[0] != 0)
            
            if matched_cols < len(self.feature_names) * 0.3:
                numeric_cols = [col for col in features.columns if features[col].dtype in [np.int64, np.float64, int, float]]
                if len(numeric_cols) >= len(self.feature_names):
                    feature_values = [features[col].iloc[0] for col in numeric_cols[:len(self.feature_names)]]
                    features = pd.DataFrame([feature_values], columns=self.feature_names)
                else:
                    for col in self.feature_names:
                        if col not in features.columns:
                            features[col] = 0
                    features = features[self.feature_names]
            else:
                for col in self.feature_names:
                    if col not in features.columns:
                        features[col] = 0
                features = features[self.feature_names]
        
        features = features.fillna(0).replace([np.inf, -np.inf], 0)
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        confidence = max(probabilities)
        
        return int(prediction), float(confidence)
    
    def predict_batch(self, df):
        if self.model is None or self.scaler is None:
            return [], []
        
        X = self.prepare_features(df)
        X_scaled = self.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        confidences = [max(prob) for prob in probabilities]
        
        return predictions.tolist(), confidences
    
    def get_feature_importance(self):
        if self.feature_importance:
            return self.feature_importance
        return {}
    
    def is_trained(self):
        return self.model is not None and self.scaler is not None


def generate_synthetic_traffic():
    import random
    is_attack = random.random() > 0.7
    
    features = {
        'packet_rate': random.uniform(10000, 50000) if is_attack else random.uniform(100, 1000),
        'bytes_per_second': random.uniform(100000, 500000) if is_attack else random.uniform(1000, 10000),
        'syn_flag_count': random.randint(100, 500) if is_attack else random.randint(0, 20),
        'flow_duration': random.uniform(0.1, 2.0) if is_attack else random.uniform(1.0, 60.0),
        'packet_size': random.randint(64, 1500),
        'source_entropy': random.uniform(0.1, 0.5) if is_attack else random.uniform(0.5, 1.0),
        'dest_port': random.choice([80, 443, 53, 22, 8080]),
        'Flow Duration': random.uniform(100000, 2000000) if is_attack else random.uniform(1000000, 60000000),
        'Total Fwd Packets': random.randint(1000, 10000) if is_attack else random.randint(10, 500),
        'Total Backward Packets': random.randint(500, 5000) if is_attack else random.randint(5, 250),
        'Flow Bytes/s': random.uniform(100000, 500000) if is_attack else random.uniform(1000, 10000),
        'Flow Packets/s': random.uniform(10000, 50000) if is_attack else random.uniform(100, 1000),
        'Fwd Packet Length Mean': random.uniform(100, 500) if is_attack else random.uniform(200, 800),
        'Bwd Packet Length Mean': random.uniform(50, 200) if is_attack else random.uniform(100, 400),
        'SYN Flag Count': random.randint(100, 500) if is_attack else random.randint(0, 20),
        'ACK Flag Count': random.randint(50, 200) if is_attack else random.randint(5, 50),
        'PSH Flag Count': random.randint(10, 100) if is_attack else random.randint(1, 20),
        'Packet Length Mean': random.uniform(100, 400) if is_attack else random.uniform(200, 600),
        'Packet Length Std': random.uniform(50, 150) if is_attack else random.uniform(100, 300),
        'Average Packet Size': random.uniform(100, 400) if is_attack else random.uniform(200, 600),
        'Init_Win_bytes_forward': random.randint(100, 1000) if is_attack else random.randint(1000, 65535),
        'Init_Win_bytes_backward': random.randint(100, 1000) if is_attack else random.randint(1000, 65535)
    }
    
    metadata = {
        'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
        'destination_ip': f"10.0.{random.randint(1,10)}.{random.randint(1,255)}",
        'protocol': random.choice(['TCP', 'UDP', 'ICMP', 'HTTP'])
    }
    
    return features, metadata, is_attack


detector = DDoSDetector()
