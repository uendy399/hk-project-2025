#!/usr/bin/env python3
"""
ML/DL Traffic Analysis Module
Combines static and dynamic analysis using machine learning and deep learning
"""

import numpy as np
import pandas as pd
from collections import defaultdict, deque
import time
import threading
from datetime import datetime
import json

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[!] Warning: scikit-learn not available. ML features will be limited.")

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, LSTM, Dropout, Conv1D, MaxPooling1D, Flatten
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("[!] Warning: TensorFlow not available. DL features will be limited.")


class MLAnalyzer:
    """Machine Learning and Deep Learning Traffic Analyzer"""
    
    def __init__(self):
        """Initialize ML/DL analyzer"""
        self.analyzing = False
        self.analysis_thread = None
        
        # Feature storage for training and analysis
        self.feature_buffer = deque(maxlen=10000)  # Store recent features
        self.anomaly_scores = deque(maxlen=1000)  # Store anomaly scores
        self.predictions = deque(maxlen=1000)  # Store predictions
        
        # ML Models
        self.isolation_forest = None
        self.traffic_classifier = None
        self.anomaly_detector_dl = None
        if SKLEARN_AVAILABLE:
            self.scaler = StandardScaler()
        else:
            self.scaler = None
        
        # Statistics
        self.stats = {
            'total_packets_analyzed': 0,
            'anomalies_detected': 0,
            'traffic_classifications': defaultdict(int),
            'attack_predictions': [],
            'feature_extraction_time': 0,
            'ml_inference_time': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Feature extraction parameters
        self.window_size = 100  # Packets per window for time-series analysis
        self.current_window = []
        
    def extract_features(self, packet_info):
        """
        Extract features from packet information for ML/DL analysis
        
        Args:
            packet_info: Dictionary containing packet information
            
        Returns:
            numpy array of features
        """
        features = []
        
        # Basic packet features
        features.append(packet_info.get('packet_size', 0))
        features.append(packet_info.get('src_port', 0))
        features.append(packet_info.get('dst_port', 0))
        features.append(packet_info.get('protocol', 0))  # TCP=6, UDP=17, etc.
        
        # Time-based features
        features.append(packet_info.get('time_delta', 0))  # Time since last packet
        features.append(packet_info.get('packet_rate', 0))  # Packets per second
        
        # Protocol-specific features
        features.append(1 if packet_info.get('is_http', False) else 0)
        features.append(1 if packet_info.get('is_https', False) else 0)
        features.append(1 if packet_info.get('is_dns', False) else 0)
        features.append(1 if packet_info.get('is_ftp', False) else 0)
        
        # Flow features
        features.append(packet_info.get('flow_duration', 0))
        features.append(packet_info.get('bytes_sent', 0))
        features.append(packet_info.get('bytes_received', 0))
        features.append(packet_info.get('packets_sent', 0))
        features.append(packet_info.get('packets_received', 0))
        
        # Statistical features
        features.append(packet_info.get('mean_packet_size', 0))
        features.append(packet_info.get('std_packet_size', 0))
        features.append(packet_info.get('mean_inter_arrival_time', 0))
        
        # Port-based features
        features.append(1 if packet_info.get('is_well_known_port', False) else 0)
        features.append(1 if packet_info.get('is_ephemeral_port', False) else 0)
        
        return np.array(features)
    
    def extract_window_features(self, window):
        """
        Extract features from a window of packets for time-series analysis
        
        Args:
            window: List of packet feature vectors
            
        Returns:
            numpy array of window features
        """
        if len(window) == 0:
            return None
        
        window_array = np.array(window)
        
        # Statistical features over window
        window_features = []
        
        # Mean, std, min, max for each feature dimension
        for i in range(window_array.shape[1]):
            window_features.append(np.mean(window_array[:, i]))
            window_features.append(np.std(window_array[:, i]))
            window_features.append(np.min(window_array[:, i]))
            window_features.append(np.max(window_array[:, i]))
        
        # Time-series specific features
        if len(window) > 1:
            # Trend features
            for i in range(min(5, window_array.shape[1])):  # First 5 features
                if len(window_array[:, i]) > 1:
                    diff = np.diff(window_array[:, i])
                    window_features.append(np.mean(diff))
                    window_features.append(np.std(diff))
        
        return np.array(window_features)
    
    def train_isolation_forest(self, features_list, contamination=0.1):
        """
        Train Isolation Forest for anomaly detection
        
        Args:
            features_list: List of feature vectors
            contamination: Expected proportion of anomalies
        """
        if not SKLEARN_AVAILABLE:
            print("[!] scikit-learn not available. Cannot train Isolation Forest.")
            return False
        
        try:
            X = np.array(features_list)
            
            # Normalize features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(X_scaled)
            
            print(f"[+] Isolation Forest trained on {len(features_list)} samples")
            return True
        except Exception as e:
            print(f"[!] Error training Isolation Forest: {e}")
            return False
    
    def train_traffic_classifier(self, features_list, labels):
        """
        Train Random Forest classifier for traffic classification
        
        Args:
            features_list: List of feature vectors
            labels: List of traffic type labels
        """
        if not SKLEARN_AVAILABLE:
            print("[!] scikit-learn not available. Cannot train classifier.")
            return False
        
        try:
            X = np.array(features_list)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Normalize features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest
            self.traffic_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                n_jobs=-1
            )
            self.traffic_classifier.fit(X_train_scaled, y_train)
            
            # Evaluate
            train_score = self.traffic_classifier.score(X_train_scaled, y_train)
            test_score = self.traffic_classifier.score(X_test_scaled, y_test)
            
            print(f"[+] Traffic Classifier trained")
            print(f"    Train accuracy: {train_score:.4f}")
            print(f"    Test accuracy: {test_score:.4f}")
            
            return True
        except Exception as e:
            print(f"[!] Error training classifier: {e}")
            return False
    
    def build_lstm_anomaly_detector(self, input_shape):
        """
        Build LSTM-based anomaly detector for time-series analysis
        
        Args:
            input_shape: Shape of input features (timesteps, features)
        """
        if not TENSORFLOW_AVAILABLE:
            print("[!] TensorFlow not available. Cannot build LSTM model.")
            return None
        
        try:
            model = Sequential([
                LSTM(64, return_sequences=True, input_shape=input_shape),
                Dropout(0.2),
                LSTM(32, return_sequences=False),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')  # Anomaly probability
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            self.anomaly_detector_dl = model
            print(f"[+] LSTM Anomaly Detector built")
            return model
        except Exception as e:
            print(f"[!] Error building LSTM model: {e}")
            return None
    
    def detect_anomaly(self, features):
        """
        Detect anomaly using Isolation Forest
        
        Args:
            features: Feature vector
            
        Returns:
            tuple: (is_anomaly, anomaly_score)
        """
        if self.isolation_forest is None or self.scaler is None:
            return False, 0.0
        
        try:
            features_array = np.array(features).reshape(1, -1)
            features_scaled = self.scaler.transform(features_array)
            
            prediction = self.isolation_forest.predict(features_scaled)[0]
            score = self.isolation_forest.score_samples(features_scaled)[0]
            
            is_anomaly = prediction == -1
            return is_anomaly, float(score)
        except Exception as e:
            # Silently handle errors to avoid affecting packet processing
            return False, 0.0
    
    def classify_traffic(self, features):
        """
        Classify traffic type using Random Forest
        
        Args:
            features: Feature vector
            
        Returns:
            tuple: (traffic_type, confidence)
        """
        if self.traffic_classifier is None or self.scaler is None:
            return "Unknown", 0.0
        
        try:
            features_array = np.array(features).reshape(1, -1)
            features_scaled = self.scaler.transform(features_array)
            
            prediction = self.traffic_classifier.predict(features_scaled)[0]
            probabilities = self.traffic_classifier.predict_proba(features_scaled)[0]
            confidence = np.max(probabilities)
            
            return str(prediction), float(confidence)
        except Exception as e:
            # Silently handle errors to avoid affecting packet processing
            return "Unknown", 0.0
    
    def detect_anomaly_dl(self, window_features):
        """
        Detect anomaly using LSTM model
        
        Args:
            window_features: Window of feature vectors
            
        Returns:
            tuple: (is_anomaly, anomaly_probability)
        """
        if self.anomaly_detector_dl is None:
            return False, 0.0
        
        try:
            # Reshape for LSTM input (samples, timesteps, features)
            window_array = np.array(window_features)
            if len(window_array.shape) == 1:
                window_array = window_array.reshape(1, 1, -1)
            else:
                window_array = window_array.reshape(1, window_array.shape[0], window_array.shape[1])
            
            prediction = self.anomaly_detector_dl.predict(window_array, verbose=0)[0][0]
            is_anomaly = prediction > 0.5
            
            return is_anomaly, float(prediction)
        except Exception as e:
            print(f"[!] Error in DL anomaly detection: {e}")
            return False, 0.0
    
    def analyze_packet(self, packet_info):
        """
        Analyze a single packet using ML/DL models
        
        Args:
            packet_info: Dictionary containing packet information
        """
        if not self.analyzing:
            return
        
        start_time = time.time()
        
        # Extract features
        features = self.extract_features(packet_info)
        self.feature_buffer.append(features)
        self.current_window.append(features)
        
        # Keep window size
        if len(self.current_window) > self.window_size:
            self.current_window.pop(0)
        
        feature_time = time.time() - start_time
        self.stats['feature_extraction_time'] += feature_time
        
        # ML-based anomaly detection
        ml_start = time.time()
        is_anomaly, anomaly_score = self.detect_anomaly(features)
        self.anomaly_scores.append({
            'timestamp': time.time(),
            'score': anomaly_score,
            'is_anomaly': is_anomaly
        })
        
        if is_anomaly:
            self.stats['anomalies_detected'] += 1
            self.stats['attack_predictions'].append({
                'type': 'Anomaly',
                'timestamp': time.time(),
                'score': anomaly_score,
                'packet_info': packet_info
            })
        
        # Traffic classification
        traffic_type, confidence = self.classify_traffic(features)
        self.stats['traffic_classifications'][traffic_type] += 1
        self.predictions.append({
            'timestamp': time.time(),
            'type': traffic_type,
            'confidence': confidence
        })
        
        # DL-based window analysis
        if len(self.current_window) >= self.window_size and self.anomaly_detector_dl:
            window_features = self.extract_window_features(self.current_window)
            if window_features is not None:
                is_dl_anomaly, dl_score = self.detect_anomaly_dl(self.current_window)
                if is_dl_anomaly:
                    self.stats['anomalies_detected'] += 1
                    self.stats['attack_predictions'].append({
                        'type': 'DL_Anomaly',
                        'timestamp': time.time(),
                        'score': dl_score,
                        'window_size': len(self.current_window)
                    })
        
        ml_time = time.time() - ml_start
        self.stats['ml_inference_time'] += ml_time
        self.stats['total_packets_analyzed'] += 1
    
    def get_statistics(self):
        """Get ML/DL analysis statistics"""
        stats = dict(self.stats)
        
        # Calculate runtime
        if stats['start_time']:
            end_time = stats['end_time'] or time.time()
            stats['duration'] = end_time - stats['start_time']
        else:
            stats['duration'] = 0
        
        # Calculate average times
        if stats['total_packets_analyzed'] > 0:
            stats['avg_feature_extraction_time'] = stats['feature_extraction_time'] / stats['total_packets_analyzed']
            stats['avg_ml_inference_time'] = stats['ml_inference_time'] / stats['total_packets_analyzed']
        else:
            stats['avg_feature_extraction_time'] = 0
            stats['avg_ml_inference_time'] = 0
        
        # Convert to regular dict
        stats['traffic_classifications'] = dict(stats['traffic_classifications'])
        
        # Recent predictions
        stats['recent_anomalies'] = list(self.anomaly_scores)[-100:]
        stats['recent_predictions'] = list(self.predictions)[-100:]
        
        # Model status
        stats['isolation_forest_trained'] = self.isolation_forest is not None
        stats['classifier_trained'] = self.traffic_classifier is not None
        stats['lstm_trained'] = self.anomaly_detector_dl is not None
        
        return stats
    
    def start_analysis(self):
        """Start ML/DL analysis"""
        if self.analyzing:
            return False
        
        self.analyzing = True
        self.stats['start_time'] = time.time()
        self.stats['total_packets_analyzed'] = 0
        self.stats['anomalies_detected'] = 0
        self.stats['traffic_classifications'].clear()
        self.stats['attack_predictions'].clear()
        self.feature_buffer.clear()
        self.anomaly_scores.clear()
        self.predictions.clear()
        self.current_window.clear()
        
        print("[+] ML/DL analysis started")
        return True
    
    def stop_analysis(self):
        """Stop ML/DL analysis"""
        if not self.analyzing:
            return False
        
        self.analyzing = False
        self.stats['end_time'] = time.time()
        
        print("[+] ML/DL analysis stopped")
        return True
    
    def export_model(self, filepath):
        """Export trained models"""
        models_data = {
            'isolation_forest_trained': self.isolation_forest is not None,
            'classifier_trained': self.traffic_classifier is not None,
            'lstm_trained': self.anomaly_detector_dl is not None,
            'scaler_params': {
                'mean_': self.scaler.mean_.tolist() if self.scaler else None,
                'scale_': self.scaler.scale_.tolist() if self.scaler else None
            } if self.scaler else None
        }
        
        with open(filepath, 'w') as f:
            json.dump(models_data, f, indent=2)
        
        # Save TensorFlow model if available
        if self.anomaly_detector_dl and TENSORFLOW_AVAILABLE:
            model_path = filepath.replace('.json', '_lstm_model')
            self.anomaly_detector_dl.save(model_path)
            print(f"[+] LSTM model saved to {model_path}")
        
        print(f"[+] Model metadata exported to {filepath}")

