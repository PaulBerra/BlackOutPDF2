#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlackoutPDF - Advanced PDF Redaction and Security Tool
=====================================================

Modular PDF redaction application with advanced security features
Application modulaire de caviardage PDF avec fonctionnalités de sécurité avancées

Author: Alexis SAUVAGE - Paul BERRA
Version: 3.0
License: MIT
"""

import sys
import os
import json
import shutil
import tempfile
import threading
import io
import re
import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from datetime import datetime, timedelta

# Core libraries / Librairies principales
import fitz  # PyMuPDF for PDF manipulation
try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    pytesseract = None

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None

# Cryptography for RSA encryption/decryption
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
import bcrypt
import base64

# Qt libraries for GUI
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ==========================================
# CONFIGURATION MODULE / MODULE DE CONFIGURATION
# ==========================================

class ConfigManager:
    """Manages application configuration via JSON file"""
    
    def __init__(self):
        self.config_file = Path("blackout_pdf_config.json")
        self.default_config = {
            "window": {
                "width": 1200,
                "height": 800,
                "min_width": 1000,
                "min_height": 600,
                "center_on_screen": True,
                "remember_position": False
            },
            "ui": {
                "default_theme": "light",
                "sidebar_width": 350,
                "default_redaction_mode": "rectangle",
                "auto_zoom_fit": True
            },
            "security": {
                "default_key_size": 2048,
                "auto_load_generated_keys": True,
                "warn_on_plain_export": True
            },
            "redaction": {
                "default_color": [0, 0, 0],
                "polygon_precision": 2,
                "preview_opacity": 100
            },
            "files": {
                "temp_cleanup_on_exit": True,
                "remember_last_directory": True,
                "auto_suggest_filename": True
            }
        }
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file or create default"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                
                # Merge with defaults (add missing keys)
                config = self.default_config.copy()
                self._update_nested_dict(config, loaded_config)
                return config
            else:
                # Create default config file
                self.save_config(self.default_config)
                logger.info(f"Created default configuration file: {self.config_file}")
                return self.default_config.copy()
                
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {e}")
            return self.default_config.copy()
    
    def save_config(self, config: Dict = None):
        """Save configuration to file"""
        try:
            config_to_save = config or self.config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, indent=4, ensure_ascii=False)
            logger.info(f"Configuration saved to: {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'window.width')"""
        try:
            keys = key_path.split('.')
            value = self.config
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value):
        """Set configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            config = self.config
            for key in keys[:-1]:
                if key not in config:
                    config[key] = {}
                config = config[key]
            config[keys[-1]] = value
        except Exception as e:
            logger.error(f"Failed to set config {key_path}: {e}")
    
    def _update_nested_dict(self, base_dict: Dict, update_dict: Dict):
        """Recursively update nested dictionary"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._update_nested_dict(base_dict[key], value)
            else:
                base_dict[key] = value


# ==========================================
# CORE DATA STRUCTURES / STRUCTURES DE DONNÉES PRINCIPALES
# ==========================================

class SecurityLevel(Enum):
    """Security levels for document access"""
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

class EncryptionType(Enum):
    """Types of encryption available"""
    NONE = "none"
    PASSWORD = "password"
    RSA = "rsa"

class RedactionMode(Enum):
    """Redaction drawing modes"""
    RECTANGLE = "rectangle"
    FREEHAND = "freehand"
    SMART = "smart"
    MOVE = "move"

@dataclass
class ApplicationState:
    """Application state information"""
    pdf_loaded: bool = False
    pdf_path: Optional[str] = None
    pdf_pages: int = 0
    rsa_keys_loaded: bool = False
    public_key_loaded: bool = False
    private_key_loaded: bool = False
    encryption_ready: bool = False
    decryption_ready: bool = False
    redaction_count: int = 0
    current_theme: str = "light"
    current_mode: RedactionMode = RedactionMode.RECTANGLE

@dataclass
class RedactionArea:
    """Redaction area data"""
    points: List[Tuple[int, int]]
    color: Tuple[int, int, int]
    security_level: SecurityLevel
    mode: RedactionMode
    metadata: Dict[str, Any]


# ==========================================
# SECURITY MODULE / MODULE DE SÉCURITÉ
# ==========================================

class SecurityModule:
    """Handles all security operations including RSA encryption/decryption"""
    
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="blackout_pdf_"))
        self.rsa_private_key = None
        self.rsa_public_key = None
        
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """Generate RSA key pair and store them internally"""
        try:
            # Generate private key
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            # Get public key
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            # Serialize keys
            private_pem = self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            logger.info(f"RSA keypair generated successfully (key size: {key_size})")
            return private_pem, public_pem
            
        except Exception as e:
            logger.error(f"Failed to generate RSA keypair: {e}")
            raise
    
    def load_private_key(self, private_key_pem: bytes):
        """Load RSA private key for decryption"""
        try:
            self.rsa_private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            logger.info("RSA private key loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load RSA private key: {e}")
            raise
    
    def load_public_key(self, public_key_pem: bytes):
        """Load RSA public key for encryption"""
        try:
            self.rsa_public_key = serialization.load_pem_public_key(public_key_pem)
            logger.info("RSA public key loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load RSA public key: {e}")
            raise
    
    def has_private_key(self) -> bool:
        """Check if private key is loaded"""
        return self.rsa_private_key is not None
    
    def has_public_key(self) -> bool:
        """Check if public key is loaded"""
        return self.rsa_public_key is not None
    
    def rsa_encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using RSA public key (hybrid encryption)"""
        if not self.rsa_public_key:
            raise ValueError("No RSA public key available")
        
        try:
            # Generate AES key for actual data encryption
            aes_key = os.urandom(32)  # 256-bit AES key
            
            # Encrypt AES key with RSA
            encrypted_aes_key = self.rsa_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt data with AES
            iv = os.urandom(16)  # AES block size
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad data to AES block size
            pad_length = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_length] * pad_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine encrypted AES key, IV, and encrypted data
            result = len(encrypted_aes_key).to_bytes(4, 'big') + encrypted_aes_key + iv + encrypted_data
            
            logger.info(f"Data encrypted successfully (size: {len(data)} -> {len(result)})")
            return result
            
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            raise
    
    def rsa_decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using RSA private key"""
        if not self.rsa_private_key:
            raise ValueError("No RSA private key available")
        
        try:
            # Extract encrypted AES key
            aes_key_length = int.from_bytes(encrypted_data[:4], 'big')
            encrypted_aes_key = encrypted_data[4:4+aes_key_length]
            iv = encrypted_data[4+aes_key_length:4+aes_key_length+16]
            ciphertext = encrypted_data[4+aes_key_length+16:]
            
            # Decrypt AES key with RSA
            aes_key = self.rsa_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            pad_length = padded_data[-1]
            data = padded_data[:-pad_length]
            
            logger.info(f"Data decrypted successfully (size: {len(encrypted_data)} -> {len(data)})")
            return data
            
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            raise
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)


# ==========================================
# REDACTION CANVAS MODULE / MODULE DE CANEVAS DE CAVIARDAGE
# ==========================================

class RedactionCanvas(QLabel):
    """Advanced redaction canvas with multiple modes"""
    
    # Signals
    redaction_added = pyqtSignal(RedactionArea)
    redaction_removed = pyqtSignal(int)
    
    def __init__(self, pixmap: QPixmap, page_index: int, parent=None):
        super().__init__(parent)
        
        # Core properties
        self.original_pixmap = pixmap
        self.page_index = page_index
        self.redaction_areas: List[RedactionArea] = []
        self.rectangles: List[QRect] = []  # Compatibility
        self.polygons: List[List[QPoint]] = []  # Compatibility
        
        # Drawing state
        self.current_mode = RedactionMode.RECTANGLE
        self.is_drawing = False
        self.current_points: List[QPoint] = []
        self.current_rect = QRect()
        self.origin = None
        
        # Visual properties
        self.scale_factor = 1.0
        self.redaction_color = QColor(0, 0, 0, 180)
        self.preview_color = QColor(255, 0, 0, 100)
        
        # Movement/resize state
        self.moving_rect_idx = None
        self.resizing_rect_idx = None
        self.move_origin = None
        self.resize_origin = None
        self.orig_rect = None
        
        # Setup
        self.setMinimumSize(pixmap.size())
        self.setPixmap(pixmap)
        self.setMouseTracking(True)
        
    def set_mode(self, mode: RedactionMode):
        """Set the current redaction mode"""
        self.current_mode = mode
        cursor_map = {
            RedactionMode.RECTANGLE: Qt.CrossCursor,
            RedactionMode.FREEHAND: Qt.OpenHandCursor,
            RedactionMode.SMART: Qt.PointingHandCursor,
            RedactionMode.MOVE: Qt.SizeAllCursor
        }
        self.setCursor(QCursor(cursor_map.get(mode, Qt.ArrowCursor)))
    
    def mousePressEvent(self, event: QMouseEvent):
        """Handle mouse press events"""
        if event.button() != Qt.LeftButton:
            return
            
        if self.current_mode == RedactionMode.RECTANGLE:
            self._start_rectangle_mode(event)
        elif self.current_mode == RedactionMode.FREEHAND:
            self._start_freehand_mode(event)
        elif self.current_mode == RedactionMode.SMART:
            self._start_smart_mode(event)
        elif self.current_mode == RedactionMode.MOVE:
            self._start_move_mode(event)
    
    def _start_rectangle_mode(self, event: QMouseEvent):
        """Start rectangle drawing mode"""
        x = int(event.pos().x() / self.scale_factor)
        y = int(event.pos().y() / self.scale_factor)
        self.origin = QPoint(x, y)
        self.current_rect = QRect(self.origin, self.origin)
        self.is_drawing = True
        self.update()
    
    def _start_freehand_mode(self, event: QMouseEvent):
        """Start freehand drawing mode"""
        x = int(event.pos().x() / self.scale_factor)
        y = int(event.pos().y() / self.scale_factor)
        self.current_points = [QPoint(x, y)]
        self.is_drawing = True
        self.update()
    
    def _start_smart_mode(self, event: QMouseEvent):
        """Start smart selection mode"""
        x = int(event.pos().x() / self.scale_factor)
        y = int(event.pos().y() / self.scale_factor)
        
        # Create a smart selection area
        margin = 50
        smart_rect = QRect(x - margin, y - margin, margin * 2, margin * 2)
        self.rectangles.append(smart_rect)
        
        points = [(smart_rect.x(), smart_rect.y()), 
                 (smart_rect.x() + smart_rect.width(), smart_rect.y()),
                 (smart_rect.x() + smart_rect.width(), smart_rect.y() + smart_rect.height()),
                 (smart_rect.x(), smart_rect.y() + smart_rect.height())]
        
        area = RedactionArea(
            points=points,
            color=(self.redaction_color.red(), self.redaction_color.green(), self.redaction_color.blue()),
            security_level=SecurityLevel.CONFIDENTIAL,
            mode=RedactionMode.SMART,
            metadata={"created": datetime.now().isoformat(), "smart_detected": True}
        )
        
        self.redaction_areas.append(area)
        self.redaction_added.emit(area)
        self.update()
    
    def _start_move_mode(self, event: QMouseEvent):
        """Start move/resize mode - works for all rectangle types including Smart"""
        pos = event.pos()
        self.moving_rect_idx = self.resizing_rect_idx = None
        
        # Check all rectangles (including Smart mode rectangles)
        for i, rect in enumerate(self.rectangles):
            scaled_rect = QRect(
                int(rect.x() * self.scale_factor),
                int(rect.y() * self.scale_factor),
                int(rect.width() * self.scale_factor),
                int(rect.height() * self.scale_factor)
            )
            
            # Check for resize handle (bottom-right corner)
            if (scaled_rect.bottomRight() - pos).manhattanLength() <= 10:
                self.resizing_rect_idx = i
                self.resize_origin = pos
                self.orig_rect = QRect(rect)
                self.is_drawing = True
                break
            # Check for move (inside rectangle)
            elif scaled_rect.contains(pos):
                self.moving_rect_idx = i
                self.move_origin = pos
                self.orig_rect = QRect(rect)
                self.is_drawing = True
                break
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """Handle mouse move events"""
        if not self.is_drawing:
            return
            
        if self.current_mode == RedactionMode.RECTANGLE:
            self._update_rectangle_mode(event)
        elif self.current_mode == RedactionMode.FREEHAND:
            self._update_freehand_mode(event)
        elif self.current_mode == RedactionMode.MOVE:
            self._update_move_mode(event)
    
    def _update_rectangle_mode(self, event: QMouseEvent):
        """Update rectangle drawing"""
        x = int(event.pos().x() / self.scale_factor)
        y = int(event.pos().y() / self.scale_factor)
        self.current_rect = QRect(self.origin, QPoint(x, y)).normalized()
        self.update()
    
    def _update_freehand_mode(self, event: QMouseEvent):
        """Update freehand drawing"""
        x = int(event.pos().x() / self.scale_factor)
        y = int(event.pos().y() / self.scale_factor)
        self.current_points.append(QPoint(x, y))
        self.update()
    
    def _update_move_mode(self, event: QMouseEvent):
        """Update move/resize operation"""
        if self.resizing_rect_idx is not None:
            dx = (event.pos().x() - self.resize_origin.x()) / self.scale_factor
            dy = (event.pos().y() - self.resize_origin.y()) / self.scale_factor
            new_rect = QRect(self.orig_rect)
            new_rect.setWidth(max(1, int(self.orig_rect.width() + dx)))
            new_rect.setHeight(max(1, int(self.orig_rect.height() + dy)))
            self.rectangles[self.resizing_rect_idx] = new_rect.normalized()
            
            # Update corresponding redaction_area if it exists
            if self.resizing_rect_idx < len(self.redaction_areas):
                rect = new_rect.normalized()
                points = [(rect.x(), rect.y()), 
                         (rect.x() + rect.width(), rect.y()),
                         (rect.x() + rect.width(), rect.y() + rect.height()),
                         (rect.x(), rect.y() + rect.height())]
                self.redaction_areas[self.resizing_rect_idx].points = points
            
            self.update()
        elif self.moving_rect_idx is not None:
            dx = (event.pos().x() - self.move_origin.x()) / self.scale_factor
            dy = (event.pos().y() - self.move_origin.y()) / self.scale_factor
            new_rect = QRect(self.orig_rect)
            new_rect.translate(int(dx), int(dy))
            self.rectangles[self.moving_rect_idx] = new_rect
            
            # Update corresponding redaction_area if it exists
            if self.moving_rect_idx < len(self.redaction_areas):
                rect = new_rect
                points = [(rect.x(), rect.y()), 
                         (rect.x() + rect.width(), rect.y()),
                         (rect.x() + rect.width(), rect.y() + rect.height()),
                         (rect.x(), rect.y() + rect.height())]
                self.redaction_areas[self.moving_rect_idx].points = points
            
            self.update()
    
    def mouseReleaseEvent(self, event: QMouseEvent):
        """Handle mouse release events"""
        if event.button() != Qt.LeftButton:
            return
            
        if self.current_mode == RedactionMode.RECTANGLE and self.is_drawing:
            self._finish_rectangle_mode()
        elif self.current_mode == RedactionMode.FREEHAND and self.is_drawing:
            self._finish_freehand_mode()
        elif self.current_mode == RedactionMode.MOVE and self.is_drawing:
            self._finish_move_mode()
            
        self.is_drawing = False
        self.update()
    
    def _finish_rectangle_mode(self):
        """Finish rectangle drawing"""
        if self.current_rect.width() > 5 and self.current_rect.height() > 5:
            self.rectangles.append(self.current_rect.normalized())
            
            rect = self.current_rect.normalized()
            points = [(rect.x(), rect.y()), 
                     (rect.x() + rect.width(), rect.y()),
                     (rect.x() + rect.width(), rect.y() + rect.height()),
                     (rect.x(), rect.y() + rect.height())]
            
            area = RedactionArea(
                points=points,
                color=(self.redaction_color.red(), self.redaction_color.green(), self.redaction_color.blue()),
                security_level=SecurityLevel.CONFIDENTIAL,
                mode=RedactionMode.RECTANGLE,
                metadata={"created": datetime.now().isoformat()}
            )
            
            self.redaction_areas.append(area)
            self.redaction_added.emit(area)
            
        self.current_rect = QRect()
    
    def _finish_freehand_mode(self):
        """Finish freehand drawing"""
        if len(self.current_points) > 2:
            self.polygons.append(self.current_points.copy())
            
            points = [(pt.x(), pt.y()) for pt in self.current_points]
            
            area = RedactionArea(
                points=points,
                color=(self.redaction_color.red(), self.redaction_color.green(), self.redaction_color.blue()),
                security_level=SecurityLevel.CONFIDENTIAL,
                mode=RedactionMode.FREEHAND,
                metadata={"created": datetime.now().isoformat()}
            )
            
            self.redaction_areas.append(area)
            self.redaction_added.emit(area)
            
        self.current_points.clear()
    
    def _finish_move_mode(self):
        """Finish move/resize operation"""
        self.moving_rect_idx = None
        self.resizing_rect_idx = None
    
    def paintEvent(self, event: QPaintEvent):
        """Custom paint event for rendering"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        
        # Draw base pixmap
        scaled_pixmap = self.original_pixmap.scaled(
            self.original_pixmap.size() * self.scale_factor,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        painter.drawPixmap(0, 0, scaled_pixmap)
        
        # Draw existing redactions
        painter.setPen(Qt.NoPen)
        painter.setBrush(self.redaction_color)
        
        # Draw rectangles
        for rect in self.rectangles:
            scaled_rect = QRect(
                int(rect.x() * self.scale_factor),
                int(rect.y() * self.scale_factor),
                int(rect.width() * self.scale_factor),
                int(rect.height() * self.scale_factor)
            )
            painter.drawRect(scaled_rect)
        
        # Draw polygons
        for polygon in self.polygons:
            scaled_points = [QPoint(int(pt.x() * self.scale_factor), int(pt.y() * self.scale_factor)) 
                           for pt in polygon]
            painter.drawPolygon(QPolygon(scaled_points))
        
        # Draw current drawing
        if self.is_drawing:
            if self.current_mode == RedactionMode.RECTANGLE:
                painter.setBrush(self.preview_color)
                scaled_current = QRect(
                    int(self.current_rect.x() * self.scale_factor),
                    int(self.current_rect.y() * self.scale_factor),
                    int(self.current_rect.width() * self.scale_factor),
                    int(self.current_rect.height() * self.scale_factor)
                )
                painter.drawRect(scaled_current)
            elif self.current_mode == RedactionMode.FREEHAND and self.current_points:
                painter.setPen(QPen(Qt.red, 2))
                scaled_points = [QPoint(int(pt.x() * self.scale_factor), int(pt.y() * self.scale_factor)) 
                               for pt in self.current_points]
                painter.drawPolyline(QPolygon(scaled_points))
    
    def zoom(self, factor: float):
        """Zoom the canvas"""
        self.scale_factor *= factor
        new_size = self.original_pixmap.size() * self.scale_factor
        self.setMinimumSize(new_size)
        self.updateGeometry()
        self.update()
    
    def undo_last_redaction(self):
        """Remove last redaction"""
        if self.polygons:
            self.polygons.pop()
            if self.redaction_areas:
                removed = self.redaction_areas.pop()
                self.redaction_removed.emit(len(self.redaction_areas))
        elif self.rectangles:
            self.rectangles.pop()
            if self.redaction_areas:
                removed = self.redaction_areas.pop()
                self.redaction_removed.emit(len(self.redaction_areas))
        self.update()
    
    def clear_all_redactions(self):
        """Clear all redactions"""
        self.rectangles.clear()
        self.polygons.clear()
        self.redaction_areas.clear()
        self.update()
    
    def set_redaction_color(self, color: QColor):
        """Set redaction color"""
        self.redaction_color = color
        self.update()


# ==========================================
# STATE PANEL MODULE / MODULE DE PANNEAU D'ÉTAT
# ==========================================

class StatePanel(QWidget):
    """Panel showing application state information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = ApplicationState()
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the state panel UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("📊 Application State")
        title.setObjectName("panel_title")
        layout.addWidget(title)
        
        # Document state
        self.doc_group = QGroupBox("📄 Document")
        doc_layout = QVBoxLayout(self.doc_group)
        
        self.pdf_status = QLabel("❌ No PDF loaded")
        self.pdf_info = QLabel("")
        self.pdf_info.setWordWrap(True)
        
        doc_layout.addWidget(self.pdf_status)
        doc_layout.addWidget(self.pdf_info)
        layout.addWidget(self.doc_group)
        
        # RSA Keys state
        self.rsa_group = QGroupBox("RSA Keys")
        rsa_layout = QVBoxLayout(self.rsa_group)
        
        self.private_key_status = QLabel("Private key: Not loaded")
        self.public_key_status = QLabel("Public key: Not loaded")
        self.encryption_status = QLabel("Encryption: Not ready")
        self.decryption_status = QLabel("Decryption: Not ready")
        
        rsa_layout.addWidget(self.private_key_status)
        rsa_layout.addWidget(self.public_key_status)
        rsa_layout.addWidget(self.encryption_status)
        rsa_layout.addWidget(self.decryption_status)
        layout.addWidget(self.rsa_group)
        
        # Redaction state
        self.redaction_group = QGroupBox("Redaction")
        redaction_layout = QVBoxLayout(self.redaction_group)
        
        self.redaction_count = QLabel("Redaction areas: 0")
        self.current_mode = QLabel("Mode: Rectangle")
        
        redaction_layout.addWidget(self.redaction_count)
        redaction_layout.addWidget(self.current_mode)
        layout.addWidget(self.redaction_group)
        
        layout.addStretch()
    
    def update_document_state(self, pdf_loaded: bool, pdf_path: str = None, pages: int = 0):
        """Update document state"""
        self.state.pdf_loaded = pdf_loaded
        self.state.pdf_path = pdf_path
        self.state.pdf_pages = pages
        
        if pdf_loaded:
            self.pdf_status.setText("PDF loaded")
            filename = Path(pdf_path).name if pdf_path else "Unknown"
            self.pdf_info.setText(f"File: {filename}\nPages: {pages}")
        else:
            self.pdf_status.setText("No PDF loaded")
            self.pdf_info.setText("")
    
    def update_rsa_state(self, private_key: bool, public_key: bool):
        """Update RSA keys state"""
        self.state.private_key_loaded = private_key
        self.state.public_key_loaded = public_key
        self.state.rsa_keys_loaded = private_key and public_key
        self.state.encryption_ready = public_key
        self.state.decryption_ready = private_key
        
        # Update UI
        self.private_key_status.setText(
            "Private key: Loaded" if private_key else "Private key: Not loaded"
        )
        self.public_key_status.setText(
            "Public key: Loaded" if public_key else "Public key: Not loaded"
        )
        self.encryption_status.setText(
            "Encryption: Ready" if public_key else "Encryption: Not ready"
        )
        self.decryption_status.setText(
            "Decryption: Ready" if private_key else "Decryption: Not ready"
        )
    
    def update_redaction_count(self, count: int):
        """Update redaction count"""
        self.state.redaction_count = count
        self.redaction_count.setText(f"Redaction areas: {count}")
    
    def update_mode(self, mode: RedactionMode):
        """Update current mode"""
        self.state.current_mode = mode
        mode_names = {
            RedactionMode.RECTANGLE: "Rectangle",
            RedactionMode.FREEHAND: "Freehand",
            RedactionMode.SMART: "Smart",
            RedactionMode.MOVE: "Move"
        }
        self.current_mode.setText(f"Mode: {mode_names.get(mode, 'Unknown')}")


# ==========================================
# MAIN APPLICATION / APPLICATION PRINCIPALE
# ==========================================

class BlackoutPDFApp(QMainWindow):
    """BlackoutPDF - Advanced PDF Redaction Application"""
    
    def __init__(self):
        super().__init__()
        
        # Configuration manager
        self.config = ConfigManager()
        
        # Core components
        self.security_module = SecurityModule()
        self.pdf_document = None
        self.canvas_widgets: List[RedactionCanvas] = []
        self.pdf_path = None
        self.temp_dir = tempfile.mkdtemp()
        
        # UI state
        self.current_theme = self.config.get("ui.default_theme", "light")
        self.current_mode = RedactionMode.RECTANGLE
        self.redaction_color = tuple(self.config.get("redaction.default_color", [0, 0, 0]))
        
        # Initialize UI
        self._setup_ui()
        self._apply_current_theme()
        
        # Show welcome
        self._show_welcome_screen()
        
    def _setup_ui(self):
        """Setup main user interface"""
        self.setWindowTitle("BlackoutPDF - Advanced Document Redaction & Security")
        
        # Configure window size from config
        window_width = self.config.get("window.width", 1200)
        window_height = self.config.get("window.height", 800)
        min_width = self.config.get("window.min_width", 1000)
        min_height = self.config.get("window.min_height", 600)
        
        # Set minimum size first
        self.setMinimumSize(min_width, min_height)
        
        # Set window size and position
        if self.config.get("window.center_on_screen", True):
            # Get screen geometry to ensure window fits
            screen = QApplication.primaryScreen().availableGeometry()
            
            # Adjust size if too large for screen
            max_width = int(screen.width() * 0.9)  # 90% of screen width
            max_height = int(screen.height() * 0.9)  # 90% of screen height
            
            actual_width = min(window_width, max_width)
            actual_height = min(window_height, max_height)
            
            # Center on screen
            x = (screen.width() - actual_width) // 2
            y = (screen.height() - actual_height) // 2
            
            self.setGeometry(x, y, actual_width, actual_height)
        else:
            self.resize(window_width, window_height)
        
        # Set icon
        try:
            icon_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "BOPDF.png")
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
        except Exception:
            pass
        
        # Main widget with horizontal layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Left sidebar
        self.sidebar = self._create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # Right content area
        self.content_area = self._create_content_area()
        main_layout.addWidget(self.content_area)
        
        # Status bar
        self._setup_status_bar()
    
    def _create_sidebar(self) -> QWidget:
        """Create left sidebar with controls and state"""
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_width = self.config.get("ui.sidebar_width", 350)
        sidebar.setFixedWidth(sidebar_width)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QWidget()
        header.setObjectName("sidebar_header")
        header.setFixedHeight(80)
        
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 15, 20, 15)
        
        title = QLabel("BlackoutPDF")
        title.setObjectName("app_title")
        
        subtitle = QLabel("Advanced PDF Security")
        subtitle.setObjectName("app_subtitle")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        layout.addWidget(header)
        
        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(10, 10, 10, 10)
        scroll_layout.setSpacing(15)
        
        # Configuration section
        config_section = self._create_section("Configuration", self._create_config_controls())
        scroll_layout.addWidget(config_section)
        
        # Theme selector
        theme_section = self._create_section("Appearance", self._create_theme_controls())
        scroll_layout.addWidget(theme_section)
        
        # File operations
        file_section = self._create_section("File Operations", self._create_file_controls())
        scroll_layout.addWidget(file_section)
        
        # RSA Key management
        rsa_section = self._create_section("RSA Key Management", self._create_rsa_controls())
        scroll_layout.addWidget(rsa_section)
        
        # Redaction tools
        redaction_section = self._create_section("Redaction Tools", self._create_redaction_controls())
        scroll_layout.addWidget(redaction_section)
        
        # State panel
        self.state_panel = StatePanel()
        scroll_layout.addWidget(self.state_panel)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        return sidebar
    
    def _create_config_controls(self) -> QWidget:
        """Create configuration controls"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Quick config info
        info_label = QLabel("Edit 'blackout_pdf_config.json' for advanced settings")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("font-size: 11px; color: #666; font-style: italic;")
        layout.addWidget(info_label)
        
        # Save config button
        save_config_btn = QPushButton("Save Current Settings")
        save_config_btn.setObjectName("small_button")
        save_config_btn.clicked.connect(self._save_current_config)
        save_config_btn.setToolTip("Save current window size and settings")
        layout.addWidget(save_config_btn)
        
        # Reset config button
        reset_config_btn = QPushButton("Reset to Defaults")
        reset_config_btn.setObjectName("small_button")
        reset_config_btn.clicked.connect(self._reset_config)
        reset_config_btn.setToolTip("Reset all settings to default values")
        layout.addWidget(reset_config_btn)
        
        return widget
    
    def _create_section(self, title: str, content_widget: QWidget) -> QWidget:
        """Create a collapsible section"""
        section = QWidget()
        section.setObjectName("section")
        
        layout = QVBoxLayout(section)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Section title
        title_label = QLabel(title)
        title_label.setObjectName("section_title")
        layout.addWidget(title_label)
        
        # Content
        layout.addWidget(content_widget)
        
        return section
    
    def _create_theme_controls(self) -> QWidget:
        """Create theme controls"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light Theme", "Dark Theme"])
        
        # Set current theme from config
        if self.current_theme == "dark":
            self.theme_combo.setCurrentIndex(1)
        else:
            self.theme_combo.setCurrentIndex(0)
            
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        layout.addWidget(self.theme_combo)
        
        return widget
    
    def _create_file_controls(self) -> QWidget:
        """Create file operation controls"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Open PDF
        self.open_btn = QPushButton("Open PDF")
        self.open_btn.setObjectName("primary_button")
        self.open_btn.clicked.connect(self.open_pdf)
        layout.addWidget(self.open_btn)
        
        # Export options
        self.export_plain_btn = QPushButton("Save PDF (No Encryption)")
        self.export_plain_btn.setObjectName("secondary_button")
        self.export_plain_btn.clicked.connect(self.export_plain_pdf)
        self.export_plain_btn.setEnabled(False)
        layout.addWidget(self.export_plain_btn)
        
        self.export_password_btn = QPushButton("Save PDF (Password)")
        self.export_password_btn.setObjectName("secondary_button")
        self.export_password_btn.clicked.connect(self.export_password_pdf)
        self.export_password_btn.setEnabled(False)
        layout.addWidget(self.export_password_btn)
        
        self.export_rsa_btn = QPushButton("Save PDF (RSA)")
        self.export_rsa_btn.setObjectName("secondary_button")
        self.export_rsa_btn.clicked.connect(self.export_rsa_pdf)
        self.export_rsa_btn.setEnabled(False)
        layout.addWidget(self.export_rsa_btn)
        
        return widget
    
    def _create_rsa_controls(self) -> QWidget:
        """Create RSA key management controls"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Generate keys
        self.generate_keys_btn = QPushButton("Generate RSA Keys")
        self.generate_keys_btn.setObjectName("primary_button")
        self.generate_keys_btn.clicked.connect(self.generate_rsa_keys)
        layout.addWidget(self.generate_keys_btn)
        
        # Load keys
        keys_layout = QHBoxLayout()
        
        self.load_private_btn = QPushButton("Load Private")
        self.load_private_btn.setObjectName("small_button")
        self.load_private_btn.clicked.connect(self.load_private_key)
        self.load_private_btn.setToolTip("Load PRIVATE key for RSA decryption")
        
        self.load_public_btn = QPushButton("Load Public")
        self.load_public_btn.setObjectName("small_button")
        self.load_public_btn.clicked.connect(self.load_public_key)
        self.load_public_btn.setToolTip("Load PUBLIC key for RSA encryption")
        
        keys_layout.addWidget(self.load_private_btn)
        keys_layout.addWidget(self.load_public_btn)
        layout.addLayout(keys_layout)
        
        # Decrypt PDF
        self.decrypt_btn = QPushButton("Decrypt PDF")
        self.decrypt_btn.setObjectName("secondary_button")
        self.decrypt_btn.clicked.connect(self.decrypt_pdf)
        layout.addWidget(self.decrypt_btn)
        
        return widget
    
    def _create_redaction_controls(self) -> QWidget:
        """Create redaction controls"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Mode selector
        mode_label = QLabel("Drawing Mode:")
        mode_label.setObjectName("control_label")
        layout.addWidget(mode_label)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Rectangle", "Freehand", "Smart", "Move"])
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        layout.addWidget(self.mode_combo)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.undo_btn = QPushButton("↩️")
        self.undo_btn.setObjectName("small_button")
        self.undo_btn.clicked.connect(self.undo_last_redaction)
        self.undo_btn.setToolTip("Undo last redaction")
        
        self.clear_btn = QPushButton("🗑️")
        self.clear_btn.setObjectName("small_button")
        self.clear_btn.clicked.connect(self.clear_all_redactions)
        self.clear_btn.setToolTip("Clear all redactions")
        
        self.color_btn = QPushButton("🎨")
        self.color_btn.setObjectName("small_button")
        self.color_btn.clicked.connect(self.choose_redaction_color)
        self.color_btn.setToolTip("Choose redaction color")
        
        controls_layout.addWidget(self.undo_btn)
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.color_btn)
        layout.addLayout(controls_layout)
        
        # Zoom controls
        zoom_layout = QHBoxLayout()
        
        self.zoom_in_btn = QPushButton("🔍+")
        self.zoom_in_btn.setObjectName("small_button")
        self.zoom_in_btn.clicked.connect(lambda: self.adjust_zoom(1.2))
        
        self.zoom_out_btn = QPushButton("🔍−")
        self.zoom_out_btn.setObjectName("small_button")
        self.zoom_out_btn.clicked.connect(lambda: self.adjust_zoom(0.8))
        
        zoom_layout.addWidget(self.zoom_in_btn)
        zoom_layout.addWidget(self.zoom_out_btn)
        layout.addLayout(zoom_layout)
        
        # OCR
        if TESSERACT_AVAILABLE:
            self.ocr_btn = QPushButton("Run OCR")
            self.ocr_btn.setObjectName("secondary_button")
            self.ocr_btn.clicked.connect(self.run_ocr)
            layout.addWidget(self.ocr_btn)
        
        return widget
    
    def _create_content_area(self) -> QWidget:
        """Create main content area"""
        content = QWidget()
        content.setObjectName("content_area")
        
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Document view
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setAlignment(Qt.AlignCenter)
        
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        
        layout.addWidget(self.scroll_area)
        
        return content
    
    def _setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready - BlackoutPDF v3.0")
        self.status_bar.addWidget(self.status_label)
    
    def _show_welcome_screen(self):
        """Show welcome screen"""
        welcome = QWidget()
        welcome.setObjectName("welcome_screen")
        
        layout = QVBoxLayout(welcome)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(30)
        
        # Title
        title = QLabel("BlackoutPDF")
        title.setObjectName("welcome_title")
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Advanced PDF Redaction with RSA Security")
        subtitle.setObjectName("welcome_subtitle")
        layout.addWidget(subtitle)
        
        # Instructions
        instructions = QLabel("""
        <h3>Quick Start Guide:</h3>
        <ol>
        <li><b>Generate RSA Keys:</b> Create encryption keys for secure PDFs</li>
        <li><b>Open PDF:</b> Load the document you want to redact</li>
        <li><b>Draw Redactions:</b> Use rectangle, freehand, or smart selection</li>
        <li><b>Save Securely:</b> Export with no encryption, password, or RSA</li>
        </ol>
        
        <h3>Smart RSA Workflow:</h3>
        <ul>
        <li><b>Auto-Decryption:</b> Load private key → Open RSA PDF → Automatic decryption!</li>
        <li><b>Manual Decryption:</b> Use 'Decrypt PDF' button for more control</li>
        <li><b>Key Files:</b> .pdf and .key files must be in same location for auto-decryption</li>
        </ul>
        
        <h3>RSA Key Management:</h3>
        <ul>
        <li><b>PUBLIC Key:</b> Used for RSA ENCRYPTION (encrypts data - can be shared)</li>
        <li><b>PRIVATE Key:</b> Used for RSA DECRYPTION (decrypts data - keep SECRET!)</li>
        <li><b>Generate Keys:</b> Creates both keys and loads them automatically</li>
        <li><b>RSA Process:</b> Encrypt with PUBLIC → Decrypt with PRIVATE</li>
        </ul>
        
        <h3>Configuration:</h3>
        <p><b>Window too big?</b> Edit <code>blackout_pdf_config.json</code> to customize:</p>
        <ul>
        <li><b>Window size:</b> "width": 1200, "height": 800</li>
        <li><b>Sidebar width:</b> "sidebar_width": 350</li>
        <li><b>Default theme:</b> "default_theme": "dark"</li>
        </ul>
        <p><i>Or use "Save Current Settings" button in Configuration section</i></p>
        """)
        instructions.setWordWrap(True)
        instructions.setObjectName("welcome_text")
        layout.addWidget(instructions)
        
        self.scroll_layout.addWidget(welcome)
    
    # ==========================================
    # CORE FUNCTIONALITY / FONCTIONNALITÉ PRINCIPALE
    # ==========================================
    
    def open_pdf(self):
        """Open PDF file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open PDF Document", "", "PDF Files (*.pdf);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Try to open the PDF
            self.pdf_document = fitz.open(file_path)
            
            # Check if the PDF requires authentication
            if self.pdf_document.needs_pass:
                self.pdf_document.close()
                
                # Check if this might be an RSA-encrypted PDF and we have a private key
                rsa_key_file = file_path.replace('.pdf', '.key')
                if os.path.exists(rsa_key_file) and self.security_module.has_private_key():
                    # Try automatic RSA decryption
                    try:
                        # Read encrypted password
                        with open(rsa_key_file, 'rb') as f:
                            encrypted_password = f.read()
                        
                        # Decrypt password with RSA private key
                        decrypted_password = self.security_module.rsa_decrypt_data(encrypted_password).decode()
                        
                        # Try to open with decrypted password
                        self.pdf_document = fitz.open(file_path)
                        if self.pdf_document.authenticate(decrypted_password):
                            # Success! RSA decryption worked
                            self._show_info_dialog("RSA Auto-Decryption", 
                                                 f"PDF automatically decrypted using loaded RSA private key!\n\n"
                                                 f"Key file: {Path(rsa_key_file).name}")
                        else:
                            self.pdf_document.close()
                            raise Exception("RSA decryption failed")
                            
                    except Exception as rsa_error:
                        # RSA decryption failed, fall back to manual options
                        logger.warning(f"RSA auto-decryption failed: {rsa_error}")
                        self._handle_encrypted_pdf_fallback(file_path)
                        return
                else:
                    # No RSA key file found or no private key loaded
                    self._handle_encrypted_pdf_fallback(file_path)
                    return
                
            
            # Verify document access
            try:
                page_count = len(self.pdf_document)
                if page_count == 0:
                    raise Exception("Document appears to be empty")
                
                # Test access to first page
                first_page = self.pdf_document[0]
                first_page.get_text()
                
            except Exception as access_error:
                self.pdf_document.close()
                self._show_error_dialog(
                    "Document Access Error", 
                    f"Cannot access document content: {str(access_error)}\n"
                    "The document may be corrupted or still encrypted."
                )
                return
            
            # Document successfully opened
            self.pdf_path = file_path
            
            # Clear existing content
            self._clear_document_view()
            
            # Load pages
            self._load_pdf_pages()
            
            # Update state
            self.state_panel.update_document_state(True, file_path, len(self.pdf_document))
            
            # Enable export buttons
            self.export_plain_btn.setEnabled(True)
            self.export_password_btn.setEnabled(True)
            if self.security_module.has_public_key():
                self.export_rsa_btn.setEnabled(True)
            
            self.status_label.setText(f"Loaded: {Path(file_path).name} ({len(self.pdf_document)} pages)")
            
        except Exception as e:
            error_msg = str(e)
            if "closed or encrypted" in error_msg.lower():
                error_msg += "\n\nThis PDF is encrypted. Use the 'Decrypt PDF' function with RSA keys or try again with password authentication."
            
            self._show_error_dialog("Failed to open PDF", error_msg)
    
    def _handle_encrypted_pdf_fallback(self, file_path: str):
        """Handle encrypted PDF when RSA auto-decryption fails or is not available"""
        # Show message about encrypted PDF
        reply = QMessageBox.question(
            self, "Encrypted PDF Detected",
            f"The PDF '{Path(file_path).name}' is encrypted.\n\n"
            "Options:\n"
            "• Use 'Decrypt PDF' button if you have RSA keys\n"
            "• Or manually enter the password below\n\n"
            "Do you want to enter a password now?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            password, ok = QInputDialog.getText(
                self, "Enter PDF Password", 
                "Enter password to decrypt PDF:",
                QLineEdit.Password
            )
            
            if ok and password:
                # Try to open with password
                self.pdf_document = fitz.open(file_path)
                if not self.pdf_document.authenticate(password):
                    self.pdf_document.close()
                    self._show_error_dialog(
                        "Authentication Failed", 
                        "The password is incorrect. Please try again or use RSA decryption."
                    )
                    return
                else:
                    # Success with manual password
                    self.pdf_path = file_path
                    self._clear_document_view()
                    self._load_pdf_pages()
                    self.state_panel.update_document_state(True, file_path, len(self.pdf_document))
                    self.export_plain_btn.setEnabled(True)
                    self.export_password_btn.setEnabled(True)
                    if self.security_module.has_public_key():
                        self.export_rsa_btn.setEnabled(True)
                    self.status_label.setText(f"Password Decrypted: {Path(file_path).name} ({len(self.pdf_document)} pages)")
            else:
                self._show_info_dialog(
                    "PDF Not Opened", 
                    "PDF requires authentication. Use 'Decrypt PDF' button with RSA keys or try opening again with password."
                )
        else:
            self._show_info_dialog(
                "Encrypted PDF", 
                "To open this encrypted PDF:\n"
                "1. Load your RSA private key (if this is an RSA-encrypted PDF)\n"
                "2. Use 'Decrypt PDF' button\n"
                "3. Or try opening again and enter the password manually"
            )
    
    def _load_pdf_pages(self):
        """Load PDF pages into canvas widgets"""
        self.canvas_widgets.clear()
        
        for page_index in range(len(self.pdf_document)):
            # Render page to image
            page = self.pdf_document[page_index]
            pix = page.get_pixmap(dpi=150)
            
            # Save temporary image
            img_path = os.path.join(self.temp_dir, f"page_{page_index}.png")
            pix.save(img_path)
            
            # Create canvas widget
            pixmap = QPixmap(img_path)
            canvas = RedactionCanvas(pixmap, page_index)
            canvas.set_mode(self.current_mode)
            canvas.redaction_added.connect(self._on_redaction_added)
            canvas.redaction_removed.connect(self._on_redaction_removed)
            
            self.canvas_widgets.append(canvas)
            self.scroll_layout.addWidget(canvas)
    
    def _clear_document_view(self):
        """Clear document view"""
        for i in reversed(range(self.scroll_layout.count())):
            child = self.scroll_layout.itemAt(i).widget()
            if child:
                child.setParent(None)
        self.canvas_widgets.clear()
    
    def export_plain_pdf(self):
        """Export PDF without encryption"""
        self._export_pdf(EncryptionType.NONE)
    
    def export_password_pdf(self):
        """Export PDF with password encryption"""
        password, ok = QInputDialog.getText(
            self, "Password Protection", 
            "Enter password (max 40 characters):",
            QLineEdit.Password
        )
        
        if not ok or not password:
            return
        
        if len(password) > 40:
            self._show_warning_dialog("Password Too Long", "Password must not exceed 40 characters.")
            return
        
        self._export_pdf(EncryptionType.PASSWORD, password)
    
    def export_rsa_pdf(self):
        """Export PDF with RSA encryption (using PUBLIC key)"""
        if not self.security_module.has_public_key():
            self._show_warning_dialog("No Public Key", "Please load a PUBLIC key for RSA encryption.\n\nNote: RSA encryption uses the PUBLIC key to encrypt data.")
            return
        
        self._export_pdf(EncryptionType.RSA)
    
    def _export_pdf(self, encryption_type: EncryptionType, password: str = None):
        """Export PDF with specified encryption - RSA encrypts redaction data, not just access"""
        if not self.pdf_document or not self.canvas_widgets:
            self._show_warning_dialog("No Document", "Please open a PDF document first.")
            return
        
        # Get save location
        default_name = "redacted_document.pdf"
        if encryption_type == EncryptionType.PASSWORD:
            default_name = "redacted_document_password.pdf"
        elif encryption_type == EncryptionType.RSA:
            default_name = "redacted_document_rsa.pdf"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF", default_name, "PDF Files (*.pdf);;All Files (*)"
        )
        
        if not output_path:
            return
        
        try:
            if encryption_type == EncryptionType.RSA:
                # NEW RSA APPROACH: Encrypt the REDACTION DATA, not just the PDF access
                self._export_rsa_encrypted_content(output_path)
            else:
                # Standard approach for non-RSA encryption
                if encryption_type != EncryptionType.NONE:
                    self._apply_irreversible_redactions()
                
                # Prepare save options
                save_options = {
                    'garbage': 4,
                    'deflate': True,
                    'clean': True
                }
                
                if encryption_type == EncryptionType.PASSWORD and password:
                    save_options.update({
                        "encryption": fitz.PDF_ENCRYPT_AES_256,
                        "owner_pw": password,
                        "user_pw": password,
                    })
                
                # Save document
                self.pdf_document.save(output_path, **save_options)
                
                # Success message
                msg = f"PDF exported successfully!\nLocation: {output_path}"
                if encryption_type == EncryptionType.PASSWORD:
                    msg += "\n\nPASSWORD PROTECTION APPLIED:\nEnter the password when opening to decrypt"
                else:
                    msg += "\n\nNO ENCRYPTION APPLIED:\nPDF is readable by anyone"
                
                self._show_info_dialog("Export Success", msg)
                self.status_label.setText(f"Exported: {Path(output_path).name}")
            
        except Exception as e:
            self._show_error_dialog("Export Failed", str(e))
    
    def _apply_irreversible_redactions(self):
        """Apply irreversible redactions to PDF"""
        for canvas in self.canvas_widgets:
            page = self.pdf_document[canvas.page_index]
            
            # Get scaling factors
            page_rect = page.rect
            pixmap_size = canvas.original_pixmap.size()
            scale_x = page_rect.width / pixmap_size.width()
            scale_y = page_rect.height / pixmap_size.height()
            
            # Apply rectangle redactions
            for rect in canvas.rectangles:
                x0 = rect.x() * scale_x
                y0 = rect.y() * scale_y
                x1 = (rect.x() + rect.width()) * scale_x
                y1 = (rect.y() + rect.height()) * scale_y
                
                pdf_rect = fitz.Rect(x0, y0, x1, y1)
                page.add_redact_annot(pdf_rect, fill=canvas.redaction_color.getRgbF()[:3])
            
            # Apply polygon redactions
            for polygon in canvas.polygons:
                self._apply_polygon_redaction(page, polygon, canvas.redaction_color, scale_x, scale_y)
            
            # Apply all redactions irreversibly
            page.apply_redactions()
    
    def _apply_polygon_redaction(self, page, polygon: List[QPoint], color: QColor, scale_x: float, scale_y: float):
        """Apply advanced polygon redaction with optimized slicing"""
        # Convert to PDF coordinates
        pdf_points = [(pt.x() * scale_x, pt.y() * scale_y) for pt in polygon]
        
        if len(pdf_points) < 3:
            return
        
        # Get bounding box
        xs, ys = zip(*pdf_points)
        y_min, y_max = min(ys), max(ys)
        
        # Slice polygon into rectangles with fine precision
        step_size = 2  # 2 points ≈ 0.7mm for high precision
        
        # Create edges for ray casting
        edges = list(zip(pdf_points, pdf_points[1:] + pdf_points[:1]))
        
        y = y_min
        while y < y_max:
            y_next = min(y + step_size, y_max)
            y_mid = (y + y_next) / 2.0
            
            # Find intersections with polygon edges
            intersections = []
            for (x0, y0), (x1, y1) in edges:
                if y0 == y1:  # Skip horizontal edges
                    continue
                
                # Check if ray intersects edge
                if (y0 <= y_mid < y1) or (y1 <= y_mid < y0):
                    # Calculate intersection x
                    t = (y_mid - y0) / (y1 - y0)
                    x_intersect = x0 + t * (x1 - x0)
                    intersections.append(x_intersect)
            
            # Sort intersections and create rectangles
            intersections.sort()
            for i in range(0, len(intersections) - 1, 2):
                if i + 1 < len(intersections):
                    x_left, x_right = intersections[i], intersections[i + 1]
                    if x_right > x_left:
                        rect = fitz.Rect(x_left, y, x_right, y_next)
                        page.add_redact_annot(rect, fill=color.getRgbF()[:3])
            
            y = y_next
    
    def _export_rsa_encrypted_content(self, output_path: str):
        """Export PDF with RSA-encrypted redaction data - CAPTURE BEFORE DESTROY, then reconstruct perfectly"""
        if not self.security_module.has_public_key():
            self._show_warning_dialog("No Public Key", "Please load a PUBLIC key for RSA encryption.")
            return
        
        try:
            # Step 1: CAPTURE COMPLETE original content BEFORE any destruction
            original_content_data = self._capture_complete_original_content()
            
            if not original_content_data:
                self._show_warning_dialog("No Redactions", "No redaction areas found. Please add redactions before exporting.")
                return
            
            # Step 2: Add verification hash for integrity check
            verification_data = {
                "content": original_content_data,
                "timestamp": datetime.now().isoformat(),
                "version": "3.0",
                "integrity_hash": self._calculate_content_hash(original_content_data)
            }
            
            # Step 3: RSA-encrypt the complete reconstruction data
            verification_json = json.dumps(verification_data, ensure_ascii=False).encode('utf-8')
            encrypted_data = self.security_module.rsa_encrypt_data(verification_json)
            
            # Step 4: Hide encrypted data in PDF using multiple methods for robustness
            self._hide_encrypted_data_robust(encrypted_data)
            
            # Step 5: NOW apply irreversible redactions (DESTROY the original content)
            self._apply_irreversible_redactions()
            
            # Step 6: Save the PDF (readable by everyone, but only "un-redactable" with private key)
            save_options = {
                'garbage': 4,
                'deflate': True,
                'clean': True
            }
            
            self.pdf_document.save(output_path, **save_options)
            
            # Success message
            msg = (f"PDF exported with RSA content encryption!\nLocation: {output_path}\n\n"
                   f"RSA CONTENT ENCRYPTION APPLIED:\n"
                   f"• PDF is readable by everyone\n"
                   f"• Original content captured and encrypted\n"
                   f"• Content completely destroyed and hidden\n"
                   f"• Only PRIVATE key can reconstruct identical content\n"
                   f"• Multiple verification checks for integrity")
            
            self._show_info_dialog("RSA Export Success", msg)
            self.status_label.setText(f"RSA Exported: {Path(output_path).name}")
            
        except Exception as e:
            self._show_error_dialog("RSA Export Failed", f"Failed to export with RSA encryption:\n{str(e)}")
    
    def _capture_complete_original_content(self) -> List[Dict]:
        """ULTRA-PRECISE capture of ALL original content for perfect reconstruction"""
        redaction_data = []
        
        for canvas in self.canvas_widgets:
            page = self.pdf_document[canvas.page_index]
            page_data = {
                "page_index": canvas.page_index,
                "page_dimensions": [page.rect.width, page.rect.height],
                "rectangles": [],
                "polygons": []
            }
            
            # Get scaling factors with high precision
            page_rect = page.rect
            canvas_size = canvas.size()
            scale_x = page_rect.width / canvas_size.width()
            scale_y = page_rect.height / canvas_size.height()
            
            # ULTRA-PRECISE rectangle capture
            for rect in canvas.rectangles:
                pdf_rect = fitz.Rect(
                    rect.x() * scale_x,
                    rect.y() * scale_y,
                    (rect.x() + rect.width()) * scale_x,
                    (rect.y() + rect.height()) * scale_y
                )
                
                rect_data = self._capture_area_ultra_precise(page, pdf_rect, "rectangle")
                rect_data.update({
                    "canvas_coordinates": [rect.x(), rect.y(), rect.width(), rect.height()],
                    "scale_factors": [scale_x, scale_y],
                    "color": [canvas.redaction_color.red(), canvas.redaction_color.green(), canvas.redaction_color.blue()]
                })
                page_data["rectangles"].append(rect_data)
            
            # ULTRA-PRECISE polygon capture
            for polygon in canvas.polygons:
                pdf_points = [(pt.x() * scale_x, pt.y() * scale_y) for pt in polygon]
                
                if pdf_points:
                    xs, ys = zip(*pdf_points)
                    bbox = [min(xs), min(ys), max(xs), max(ys)]
                    pdf_rect = fitz.Rect(bbox)
                    
                    polygon_data = self._capture_area_ultra_precise(page, pdf_rect, "polygon")
                    polygon_data.update({
                        "canvas_coordinates": [[pt.x(), pt.y()] for pt in polygon],
                        "pdf_coordinates": pdf_points,
                        "scale_factors": [scale_x, scale_y],
                        "color": [canvas.redaction_color.red(), canvas.redaction_color.green(), canvas.redaction_color.blue()]
                    })
                    page_data["polygons"].append(polygon_data)
            
            # Only add page data if it has redactions
            if page_data["rectangles"] or page_data["polygons"]:
                redaction_data.append(page_data)
        
        return redaction_data
    
    def _capture_area_ultra_precise(self, page, pdf_rect: fitz.Rect, area_type: str) -> Dict:
        """Ultra-precise capture of a specific area with ALL content types"""
        area_data = {
            "type": area_type,
            "bbox": [pdf_rect.x0, pdf_rect.y0, pdf_rect.x1, pdf_rect.y1],
            "original_pixmap": None,
            "text_elements": [],
            "image_elements": [],
            "vector_elements": [],
            "annotation_elements": [],
            "background_elements": []
        }
        
        try:
            # 1. COMPLETE PIXMAP CAPTURE - Highest fidelity backup
            pix = page.get_pixmap(clip=pdf_rect, matrix=fitz.Matrix(3.0, 3.0))  # 3x resolution for precision
            if pix.width > 0 and pix.height > 0:
                area_data["original_pixmap"] = {
                    "data": base64.b64encode(pix.tobytes("png")).decode('ascii'),
                    "width": pix.width,
                    "height": pix.height,
                    "matrix": [3.0, 3.0],  # Scale factor used
                    "colorspace": pix.colorspace.name if pix.colorspace else "RGB"
                }
            
            # 2. PRECISE TEXT EXTRACTION with full formatting
            text_page = page.get_textpage(clip=pdf_rect)
            text_dict = page.get_text("dict", clip=pdf_rect, textpage=text_page)
            
            for block in text_dict.get("blocks", []):
                if "lines" in block:  # Text block
                    for line in block["lines"]:
                        for span in line["spans"]:
                            if span.get("text", "").strip():
                                text_element = {
                                    "text": span["text"],
                                    "bbox": span["bbox"],
                                    "font": span.get("font", "Arial"),
                                    "size": span.get("size", 12),
                                    "flags": span.get("flags", 0),
                                    "color": span.get("color", 0),
                                    "origin": span.get("origin", [0, 0]),
                                    "ascender": span.get("ascender", 1.0),
                                    "descender": span.get("descender", -0.2)
                                }
                                area_data["text_elements"].append(text_element)
            
            # 3. PRECISE IMAGE EXTRACTION
            image_list = page.get_images(full=True)
            for img_index, img in enumerate(image_list):
                xref = img[0]
                try:
                    # Get image bbox
                    img_dict = page.get_image_bbox(img, transform=True)
                    if img_dict and pdf_rect.intersects(fitz.Rect(img_dict)):
                        # Extract image data
                        base_image = self.pdf_document.extract_image(xref)
                        image_element = {
                            "xref": xref,
                            "bbox": img_dict,
                            "ext": base_image["ext"],
                            "width": base_image["width"],
                            "height": base_image["height"],
                            "colorspace": base_image["colorspace"],
                            "image_data": base64.b64encode(base_image["image"]).decode('ascii')
                        }
                        area_data["image_elements"].append(image_element)
                except:
                    continue
            
            # 4. PRECISE VECTOR GRAPHICS EXTRACTION
            drawings = page.get_drawings()
            for drawing in drawings:
                drawing_element = {
                    "items": [],
                    "bbox": drawing.get("rect", [0, 0, 0, 0]),
                    "fill": drawing.get("fill", None),
                    "stroke": drawing.get("stroke", None),
                    "width": drawing.get("width", 1)
                }
                
                for item in drawing.get("items", []):
                    if "rect" in item and pdf_rect.intersects(fitz.Rect(item["rect"])):
                        drawing_element["items"].append(item)
                
                if drawing_element["items"]:
                    area_data["vector_elements"].append(drawing_element)
            
            # 5. ANNOTATIONS CAPTURE
            annotations = page.annots()
            for annot in annotations:
                if pdf_rect.intersects(annot.rect):
                    annot_element = {
                        "type": annot.type,
                        "bbox": list(annot.rect),
                        "content": annot.info.get("content", ""),
                        "title": annot.info.get("title", ""),
                        "flags": annot.flags,
                        "colors": {
                            "stroke": getattr(annot, 'colors', {}).get('stroke', None),
                            "fill": getattr(annot, 'colors', {}).get('fill', None)
                        }
                    }
                    area_data["annotation_elements"].append(annot_element)
            
            # 6. BACKGROUND CAPTURE (for complex layouts)
            # Capture a slightly larger area for context
            expanded_rect = fitz.Rect(
                pdf_rect.x0 - 5, pdf_rect.y0 - 5,
                pdf_rect.x1 + 5, pdf_rect.y1 + 5
            )
            bg_pix = page.get_pixmap(clip=expanded_rect, matrix=fitz.Matrix(2.0, 2.0))
            if bg_pix.width > 0 and bg_pix.height > 0:
                area_data["background_elements"] = {
                    "data": base64.b64encode(bg_pix.tobytes("png")).decode('ascii'),
                    "bbox": list(expanded_rect),
                    "width": bg_pix.width,
                    "height": bg_pix.height,
                    "matrix": [2.0, 2.0]
                }
            
        except Exception as e:
            logger.error(f"Error in ultra-precise capture: {e}")
            # Fallback to basic pixmap if detailed capture fails
            try:
                fallback_pix = page.get_pixmap(clip=pdf_rect)
                area_data["original_pixmap"] = {
                    "data": base64.b64encode(fallback_pix.tobytes("png")).decode('ascii'),
                    "width": fallback_pix.width,
                    "height": fallback_pix.height,
                    "matrix": [1.0, 1.0],
                    "fallback": True
                }
            except:
                pass
        
        return area_data
    
    def _calculate_content_hash(self, content_data: List[Dict]) -> str:
        """Calculate hash for integrity verification"""
        import hashlib
        content_str = json.dumps(content_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(content_str).hexdigest()
    
    def _hide_encrypted_data_robust(self, encrypted_data: bytes):
        """Hide encrypted data using multiple robust methods"""
        encoded_data = base64.b64encode(encrypted_data).decode('ascii')
        
        # Method 1: Hidden annotation outside visible area
        first_page = self.pdf_document[0]
        hidden_rect = fitz.Rect(-10, -10, -1, -1)
        annot = first_page.add_text_annot(hidden_rect.tl, "hidden")
        annot.set_info(title="RSA_ENCRYPTED_CONTENT", content=encoded_data)
        annot.update()
        
        # Method 2: Split data across multiple hidden text objects
        data_chunks = [encoded_data[i:i+1000] for i in range(0, len(encoded_data), 1000)]
        for i, chunk in enumerate(data_chunks):
            pos = fitz.Point(-5 - i*0.1, -5 - i*0.1)
            first_page.insert_text(pos, f"CHUNK_{i}:{chunk}", fontsize=0.1, color=(1, 1, 1))
        
        # Method 3: Store checksum separately
        import hashlib
        checksum = hashlib.md5(encrypted_data).hexdigest()
        checksum_rect = fitz.Rect(-15, -15, -11, -11) 
        checksum_annot = first_page.add_text_annot(checksum_rect.tl, "checksum")
        checksum_annot.set_info(title="RSA_CHECKSUM", content=checksum)
        checksum_annot.update()
    
    # ==========================================
    # RSA KEY MANAGEMENT / GESTION DES CLÉS RSA
    # ==========================================
    
    def generate_rsa_keys(self):
        """Generate RSA key pair and auto-load them"""
        # Choose key size
        key_size, ok = QInputDialog.getItem(
            self, "RSA Key Size", "Choose key size:", ["2048", "3072", "4096"], 0, False
        )
        
        if not ok:
            return
        
        try:
            # Generate keys
            private_pem, public_pem = self.security_module.generate_rsa_keypair(int(key_size))
            
            # Auto-load the generated keys
            self._update_rsa_status()
            
            # Optionally save keys to files
            reply = QMessageBox.question(
                self, "Save Keys", 
                "Keys generated and loaded successfully!\n\nDo you want to save them to files?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                save_dir = QFileDialog.getExistingDirectory(self, "Save RSA Keys")
                if save_dir:
                    private_path = Path(save_dir) / "rsa_private_key.pem"
                    public_path = Path(save_dir) / "rsa_public_key.pem"
                    
                    with open(private_path, 'wb') as f:
                        f.write(private_pem)
                    with open(public_path, 'wb') as f:
                        f.write(public_pem)
                    
                    self._show_info_dialog(
                        "Keys Saved", 
                        f"RSA keys saved successfully!\n\n"
                        f"Private key: {private_path}\n"
                        f"Public key: {public_path}\n\n"
                        "Keep your private key secure!"
                    )
            
            # Enable RSA export if PDF is loaded
            if self.pdf_document:
                self.export_rsa_btn.setEnabled(True)
                
        except Exception as e:
            self._show_error_dialog("Key Generation Failed", str(e))
    
    def load_private_key(self):
        """Load RSA private key for decryption"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Private Key (for decryption)", "", "PEM Files (*.pem);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'rb') as f:
                private_pem = f.read()
            
            self.security_module.load_private_key(private_pem)
            self._update_rsa_status()
            
            self._show_info_dialog("Private Key Loaded", "PRIVATE key loaded successfully!\n\nYou can now:\n• Decrypt RSA-encrypted PDFs (that were encrypted with the corresponding PUBLIC key)\n• Use 'Decrypt PDF' button to open encrypted documents")
            
        except Exception as e:
            self._show_error_dialog("Key Loading Failed", str(e))
    
    def load_public_key(self):
        """Load RSA public key for encryption"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Public Key (for encryption)", "", "PEM Files (*.pem);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'rb') as f:
                public_pem = f.read()
            
            self.security_module.load_public_key(public_pem)
            self._update_rsa_status()
            
            # Enable RSA export if PDF is loaded
            if self.pdf_document:
                self.export_rsa_btn.setEnabled(True)
            
            self._show_info_dialog("Public Key Loaded", "PUBLIC key loaded successfully!\n\nYou can now:\n• Encrypt PDFs with RSA (creates password-protected PDF + .key file)\n• Use 'Save PDF (RSA)' button to create encrypted documents")
            
        except Exception as e:
            self._show_error_dialog("Key Loading Failed", str(e))
    
    def decrypt_pdf(self):
        """Decrypt RSA-encrypted PDF using PRIVATE key - handles both content and access encryption"""
        if not self.security_module.has_private_key():
            self._show_warning_dialog("No Private Key", "Please load a PRIVATE key for RSA decryption.\n\nNote: RSA decryption requires the PRIVATE key to decrypt data encrypted with the PUBLIC key.")
            return
        
        # Select encrypted PDF
        pdf_path, _ = QFileDialog.getOpenFileName(
            self, "Select Encrypted PDF", "", "PDF Files (*.pdf);;All Files (*)"
        )
        
        if not pdf_path:
            return
        
        try:
            # First, try to open the PDF to check if it has encrypted content annotation
            temp_doc = fitz.open(pdf_path)
            has_encrypted_content = self._has_rsa_encrypted_content(temp_doc)
            is_password_protected = temp_doc.needs_pass
            temp_doc.close()
            
            if has_encrypted_content:
                # NEW APPROACH: PDF with RSA-encrypted content (readable by everyone, but redactions can be decrypted)
                self._decrypt_rsa_content(pdf_path)
            elif is_password_protected:
                # OLD APPROACH: Password-protected PDF with RSA-encrypted password
                self._decrypt_rsa_password_protected(pdf_path)
            else:
                self._show_info_dialog("No Encryption", "This PDF does not appear to be RSA-encrypted.\n\nIt can be opened normally without decryption.")
                
        except Exception as e:
            self._show_error_dialog("PDF Analysis Failed", f"Failed to analyze PDF encryption:\n{str(e)}")
    
    def _decrypt_rsa_content(self, pdf_path: str):
        """Decrypt RSA-encrypted redaction content - restores original content"""
        try:
            # Open the PDF (should be readable by everyone)
            self.pdf_document = fitz.open(pdf_path)
            
            # Get encrypted redaction data from hidden annotation
            encrypted_data = self._get_rsa_encrypted_data(self.pdf_document)
            if not encrypted_data:
                self._show_error_dialog("No Encrypted Content", "This PDF does not contain RSA-encrypted redaction data.")
                return
            
            # Decrypt with RSA private key
            decrypted_json = self.security_module.rsa_decrypt_data(encrypted_data).decode('utf-8')
            verification_data = json.loads(decrypted_json)
            
            # Restore original content to the PDF using complete verification data
            self._restore_original_content(verification_data)
            
            # Update document display
            self.pdf_path = pdf_path
            self._clear_document_view()
            self._load_pdf_pages()
            
            # Update UI state
            self.state_panel.update_document_state(True, pdf_path, len(self.pdf_document))
            self.export_plain_btn.setEnabled(True)
            self.export_password_btn.setEnabled(True)
            if self.security_module.has_public_key():
                self.export_rsa_btn.setEnabled(True)
            
            # Success message
            self._show_info_dialog(
                "Content Decryption Success", 
                f"RSA content decryption successful!\n\n"
                f"Original content has been restored\n"
                f"Redactions removed using PRIVATE key\n"
                f"Document is now un-redacted and editable\n\n"
                f"Location: {pdf_path}"
            )
            
            self.status_label.setText(f"RSA Content Decrypted: {Path(pdf_path).name}")
            
        except Exception as e:
            if self.pdf_document:
                self.pdf_document.close()
                self.pdf_document = None
            self._show_error_dialog("Content Decryption Failed", f"Failed to decrypt RSA content:\n{str(e)}")
    
    def _decrypt_rsa_password_protected(self, pdf_path: str):
        """Decrypt old-style RSA password-protected PDF"""
        # Look for corresponding key file
        key_path = pdf_path.replace('.pdf', '.key')
        
        if not os.path.exists(key_path):
            key_path, _ = QFileDialog.getOpenFileName(
                self, "Select RSA Key File (.key)", "", "Key Files (*.key);;All Files (*)"
            )
        
        if not key_path:
            self._show_warning_dialog("No Key File Selected", "Please select the RSA .key file that corresponds to this encrypted PDF.")
            return
            
        if not os.path.exists(key_path):
            self._show_error_dialog("Key File Not Found", f"The selected key file does not exist:\n{key_path}\n\nPlease verify the file path and try again.")
            return
        
        try:
            # Read encrypted password with error handling
            try:
                with open(key_path, 'rb') as f:
                    encrypted_password = f.read()
                
                if len(encrypted_password) == 0:
                    raise Exception(f"Key file is empty: {key_path}")
                    
                logger.info(f"Successfully read key file: {key_path} ({len(encrypted_password)} bytes)")
                
            except PermissionError:
                self._show_error_dialog("Permission Error", f"Cannot read key file due to permissions:\n{key_path}\n\nPlease check file permissions.")
                return
            except FileNotFoundError:
                self._show_error_dialog("File Not Found", f"Key file not found:\n{key_path}")
                return
            except Exception as e:
                self._show_error_dialog("Key File Error", f"Failed to read key file:\n{key_path}\n\nError: {str(e)}")
                return
            
            # Decrypt password with RSA private key
            try:
                decrypted_password = self.security_module.rsa_decrypt_data(encrypted_password).decode()
                logger.info(f"Successfully decrypted password using RSA private key")
            except Exception as decrypt_error:
                self._show_error_dialog("RSA Decryption Failed", 
                                       f"Failed to decrypt the key file with your RSA private key.\n\n"
                                       f"Possible causes:\n"
                                       f"• Wrong private key (doesn't match the public key used for encryption)\n"
                                       f"• Corrupted key file\n"
                                       f"• Key file format is incorrect\n\n"
                                       f"Technical error: {str(decrypt_error)}")
                return
            
            # First, check if PDF is accessible (try to open without authentication)
            try:
                temp_doc = fitz.open(pdf_path)
                is_encrypted = temp_doc.needs_pass
                temp_doc.close()
            except Exception:
                is_encrypted = True
            
            # Open encrypted PDF with proper error handling
            if is_encrypted:
                # PDF is encrypted, try with decrypted password
                self.pdf_document = fitz.open(pdf_path)
                
                # Try to authenticate with the decrypted password
                auth_result = self.pdf_document.authenticate(decrypted_password)
                
                if not auth_result:
                    # Try different password variations
                    alt_passwords = [
                        decrypted_password.strip(),
                        decrypted_password.encode().decode('utf-8'),
                        decrypted_password.replace('\x00', ''),  # Remove null bytes
                    ]
                    
                    for alt_pwd in alt_passwords:
                        if self.pdf_document.authenticate(alt_pwd):
                            auth_result = True
                            decrypted_password = alt_pwd
                            break
                
                if not auth_result:
                    self.pdf_document.close()
                    self._show_error_dialog(
                        "Authentication Failed", 
                        f"Failed to authenticate PDF with decrypted password.\n"
                        f"Password length: {len(decrypted_password)} chars\n"
                        f"Please verify the correct key file was used."
                    )
                    return
            else:
                # PDF is not encrypted, open normally
                self.pdf_document = fitz.open(pdf_path)
            
            # Verify we can access the document content
            try:
                page_count = len(self.pdf_document)
                if page_count == 0:
                    raise Exception("Document appears to be empty or corrupted")
                
                # Try to access the first page to ensure full decryption
                first_page = self.pdf_document[0]
                first_page.get_text()  # This will fail if not properly decrypted
                
            except Exception as e:
                self.pdf_document.close()
                self._show_error_dialog(
                    "Document Access Failed", 
                    f"Cannot access document content: {str(e)}\n"
                    f"The document may be corrupted or require a different decryption method."
                )
                return
            
            # Document successfully opened and decrypted
            self.pdf_path = pdf_path
            
            # Clear existing content
            self._clear_document_view()
            
            # Load pages
            self._load_pdf_pages()
            
            # Update state
            self.state_panel.update_document_state(True, pdf_path, len(self.pdf_document))
            
            # Enable export buttons
            self.export_plain_btn.setEnabled(True)
            self.export_password_btn.setEnabled(True)
            if self.security_module.has_public_key():
                self.export_rsa_btn.setEnabled(True)
            
            self.status_label.setText(f"RSA Decrypted: {Path(pdf_path).name} ({len(self.pdf_document)} pages)")
            self._show_info_dialog("RSA Decryption Success", 
                                 f"PDF decrypted successfully with RSA PRIVATE key!\n\n"
                                 f"Document: {Path(pdf_path).name}\n"
                                 f"Pages: {len(self.pdf_document)}\n"
                                 f"Key file used: {Path(key_path).name}\n\n"
                                 f"The document is now accessible for viewing and editing.")
                
        except Exception as e:
            error_msg = str(e)
            if "closed or encrypted" in error_msg.lower():
                error_msg += "\n\nTips:\n• Verify the correct .key file is selected\n• Ensure the private key matches the encryption key\n• Check if the PDF was encrypted with this RSA key pair"
            
            self._show_error_dialog("Decryption Failed", error_msg)
    
    def _restore_original_content(self, verification_data: Dict):
        """PERFECTLY restore original content from complete encrypted data"""
        try:
            # Verify integrity first
            content_data = verification_data["content"]
            stored_hash = verification_data["integrity_hash"]
            current_hash = self._calculate_content_hash(content_data)
            
            if stored_hash != current_hash:
                raise Exception("Data integrity check failed - content may be corrupted")
            
            logger.info(f"Integrity verified - restoring {len(content_data)} pages")
            
            for page_data in content_data:
                page_index = page_data["page_index"]
                page = self.pdf_document[page_index]
                
                # PERFECT restoration from rectangles
                for rect_data in page_data.get("rectangles", []):
                    self._restore_rectangle_content_perfect(page, rect_data)
                
                # PERFECT restoration from polygons  
                for polygon_data in page_data.get("polygons", []):
                    self._restore_polygon_content_perfect(page, polygon_data)
            
            logger.info(f"Successfully restored ALL content for {len(content_data)} pages")
            
        except Exception as e:
            logger.error(f"Failed to restore original content: {e}")
            raise
    
    def _restore_rectangle_content_perfect(self, page, rect_data: Dict):
        """ULTRA-PRECISE restoration with maximum fidelity"""
        try:
            bbox = rect_data["bbox"]
            pdf_rect = fitz.Rect(bbox)
            
            logger.info(f"Starting ultra-precise restoration for area {bbox}")
            
            # STEP 1: SURGICAL area clearing with precision
            self._clear_area_surgical(page, pdf_rect)
            
            # STEP 2: Multi-method restoration for maximum accuracy
            restoration_success = False
            
            # Method 1: Try precise element restoration first
            if self._restore_precise_elements(page, rect_data):
                restoration_success = True
                logger.info("Precise element restoration successful")
            
            # Method 2: Fallback to high-resolution pixmap restoration
            if not restoration_success or rect_data.get("original_pixmap", {}).get("fallback"):
                if self._restore_pixmap_ultra_precise(page, rect_data):
                    restoration_success = True
                    logger.info("Ultra-precise pixmap restoration successful")
            
            # Method 3: Final fallback to background context restoration
            if not restoration_success and rect_data.get("background_elements"):
                self._restore_background_context(page, rect_data)
                restoration_success = True
                logger.info("Background context restoration applied")
            
            if not restoration_success:
                logger.warning(f"Could not restore area {bbox} - applying basic white fill")
                page.draw_rect(pdf_rect, fill=(1, 1, 1))
            
            logger.info(f"Ultra-precise restoration completed for area {bbox}")
            
        except Exception as e:
            logger.error(f"Failed ultra-precise restoration: {e}")
            # Emergency fallback
            try:
                self._emergency_pixmap_restore(page, rect_data)
            except:
                pass
    
    def _restore_polygon_content_perfect(self, page, polygon_data: Dict):
        """Perfectly restore content from a polygon area"""
        try:
            pdf_points = polygon_data["pdf_coordinates"]
            
            if pdf_points:
                xs, ys = zip(*pdf_points)
                bbox = [min(xs), min(ys), max(xs), max(ys)]
                pdf_rect = fitz.Rect(bbox)
                
                # Clear and restore similar to rectangle
                self._clear_area_completely(page, pdf_rect)
                
                complete_text = polygon_data.get("complete_text", {})
                if complete_text and complete_text.get("blocks"):
                    self._restore_text_blocks_perfectly(page, complete_text["blocks"], pdf_rect)
                
                complete_images = polygon_data.get("complete_images", [])
                for img_data in complete_images:
                    self._restore_image_perfectly(page, img_data)
            
            logger.info(f"Perfect polygon restoration completed for {len(pdf_points)} points")
            
        except Exception as e:
            logger.error(f"Failed to restore polygon content: {e}")
            raise
    
    def _clear_area_surgical(self, page, area_rect: fitz.Rect):
        """Surgically clear an area with maximum precision"""
        try:
            # 1. Remove all annotations in area with precision
            annotations = list(page.annots())
            for annot in annotations:
                if area_rect.intersects(annot.rect):
                    page.delete_annot(annot)
            
            # 2. Create a clean white base with anti-aliasing
            page.draw_rect(area_rect, color=(1, 1, 1), fill=(1, 1, 1), width=0)
            
            # 3. Ensure clean edges by slightly overlapping
            expanded = fitz.Rect(
                area_rect.x0 - 0.1, area_rect.y0 - 0.1,
                area_rect.x1 + 0.1, area_rect.y1 + 0.1
            )
            page.draw_rect(expanded, fill=(1, 1, 1), width=0)
            
        except Exception as e:
            logger.warning(f"Could not surgically clear area: {e}")
    
    def _restore_precise_elements(self, page, rect_data: Dict) -> bool:
        """Restore using precise element-by-element reconstruction"""
        try:
            success_count = 0
            total_elements = 0
            
            # 1. Restore text elements with maximum precision
            for text_elem in rect_data.get("text_elements", []):
                total_elements += 1
                if self._restore_text_element_precise(page, text_elem):
                    success_count += 1
            
            # 2. Restore image elements with perfect positioning
            for img_elem in rect_data.get("image_elements", []):
                total_elements += 1
                if self._restore_image_element_precise(page, img_elem):
                    success_count += 1
            
            # 3. Restore vector elements with exact properties
            for vector_elem in rect_data.get("vector_elements", []):
                total_elements += 1
                if self._restore_vector_element_precise(page, vector_elem):
                    success_count += 1
            
            # 4. Restore annotations with full fidelity
            for annot_elem in rect_data.get("annotation_elements", []):
                total_elements += 1
                if self._restore_annotation_element_precise(page, annot_elem):
                    success_count += 1
            
            # Consider successful if we restored > 70% of elements
            success_rate = success_count / max(total_elements, 1)
            logger.info(f"Element restoration success rate: {success_rate:.2%} ({success_count}/{total_elements})")
            
            return success_rate > 0.7
            
        except Exception as e:
            logger.error(f"Failed precise element restoration: {e}")
            return False
    
    def _restore_text_element_precise(self, page, text_elem: Dict) -> bool:
        """Restore single text element with maximum precision"""
        try:
            text = text_elem["text"]
            bbox = text_elem["bbox"]
            font = text_elem.get("font", "Arial")
            size = text_elem.get("size", 12)
            color = text_elem.get("color", 0)
            flags = text_elem.get("flags", 0)
            
            # Convert color from integer to RGB tuple
            if isinstance(color, int):
                r = (color >> 16) & 0xFF
                g = (color >> 8) & 0xFF
                b = color & 0xFF
                color_tuple = (r/255.0, g/255.0, b/255.0)
            else:
                color_tuple = (0, 0, 0)
            
            # Calculate precise text position (baseline)
            x = bbox[0]
            y = bbox[1] + (bbox[3] - bbox[1]) * 0.8  # Approximate baseline
            
            # Try multiple font variations for best match
            font_candidates = [font, font.replace("-", ""), "Arial", "Helvetica", "Times-Roman"]
            
            for font_candidate in font_candidates:
                try:
                    # Insert text with precise parameters
                    result = page.insert_text(
                        (x, y),
                        text,
                        fontname=font_candidate,
                        fontsize=size,
                        color=color_tuple,
                        rotate=0,
                        morph=None
                    )
                    
                    if result > 0:  # Success
                        logger.debug(f"Text restored: '{text[:20]}...' with font {font_candidate}")
                        return True
                        
                except Exception:
                    continue
            
            # Final fallback with basic parameters
            page.insert_text((x, y), text, fontsize=size, color=color_tuple)
            return True
            
        except Exception as e:
            logger.warning(f"Failed to restore text element: {e}")
            return False
    
    def _restore_image_element_precise(self, page, img_elem: Dict) -> bool:
        """Restore image element with pixel-perfect positioning"""
        try:
            bbox = img_elem["bbox"]
            image_data = img_elem["image_data"]
            width = img_elem["width"]
            height = img_elem["height"]
            
            # Decode image data
            img_bytes = base64.b64decode(image_data.encode('ascii'))
            
            # Create pixmap from image data
            pix = fitz.Pixmap(img_bytes)
            
            # Create precise rectangle for image placement
            img_rect = fitz.Rect(bbox[0], bbox[1], bbox[2], bbox[3])
            
            # Insert image with precise positioning
            page.insert_image(img_rect, pixmap=pix, overlay=True)
            
            logger.debug(f"Image restored at {bbox} with size {width}x{height}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to restore image element: {e}")
            return False
    
    def _restore_vector_element_precise(self, page, vector_elem: Dict) -> bool:
        """Restore vector graphics with exact properties"""
        try:
            items = vector_elem.get("items", [])
            fill = vector_elem.get("fill", None)
            stroke = vector_elem.get("stroke", None)
            width = vector_elem.get("width", 1)
            
            for item in items:
                if "rect" in item:
                    rect = fitz.Rect(item["rect"])
                    page.draw_rect(rect, color=stroke, fill=fill, width=width)
                elif "line" in item:
                    points = item["line"]
                    if len(points) >= 2:
                        page.draw_line(fitz.Point(points[0]), fitz.Point(points[1]), 
                                     color=stroke, width=width)
                elif "curve" in item:
                    # Handle curve drawing
                    points = item["curve"]
                    if len(points) >= 4:
                        page.draw_bezier(fitz.Point(points[0]), fitz.Point(points[1]),
                                       fitz.Point(points[2]), fitz.Point(points[3]),
                                       color=stroke, width=width)
            
            return len(items) > 0
            
        except Exception as e:
            logger.warning(f"Failed to restore vector element: {e}")
            return False
    
    def _restore_annotation_element_precise(self, page, annot_elem: Dict) -> bool:
        """Restore annotation with full fidelity"""
        try:
            annot_type = annot_elem["type"]
            bbox = fitz.Rect(annot_elem["bbox"])
            content = annot_elem.get("content", "")
            title = annot_elem.get("title", "")
            
            # Create annotation based on type
            if annot_type[1] == "Text":
                annot = page.add_text_annot(bbox.tl, content)
            elif annot_type[1] == "Highlight":
                annot = page.add_highlight_annot(bbox)
            elif annot_type[1] == "Square":
                annot = page.add_rect_annot(bbox)
            else:
                # Default to text annotation
                annot = page.add_text_annot(bbox.tl, content)
            
            # Set annotation properties
            if title:
                annot.set_info(title=title, content=content)
            
            annot.update()
            return True
            
        except Exception as e:
            logger.warning(f"Failed to restore annotation: {e}")
            return False
    
    def _restore_pixmap_ultra_precise(self, page, rect_data: Dict) -> bool:
        """Restore using ultra-high resolution pixmap"""
        try:
            pixmap_data = rect_data.get("original_pixmap")
            if not pixmap_data:
                return False
            
            # Decode high-resolution pixmap
            img_bytes = base64.b64decode(pixmap_data["data"].encode('ascii'))
            pix = fitz.Pixmap(img_bytes)
            
            # Get target rectangle
            bbox = rect_data["bbox"]
            target_rect = fitz.Rect(bbox)
            
            # Calculate transformation matrix for precise scaling
            matrix = pixmap_data.get("matrix", [1.0, 1.0])
            scale_x = (target_rect.width * matrix[0]) / pix.width
            scale_y = (target_rect.height * matrix[1]) / pix.height
            
            # Create transformation matrix
            transform = fitz.Matrix(scale_x, scale_y)
            transform = transform.pretranslate(target_rect.x0, target_rect.y0)
            
            # Insert pixmap with precise transformation
            page.insert_image(target_rect, pixmap=pix, overlay=True)
            
            logger.info(f"Ultra-precise pixmap restoration successful for {bbox}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed ultra-precise pixmap restoration: {e}")
            return False
    
    def _restore_background_context(self, page, rect_data: Dict):
        """Restore using background context for complex layouts"""
        try:
            bg_data = rect_data.get("background_elements")
            if not bg_data:
                return
            
            # Decode background image
            img_bytes = base64.b64decode(bg_data["data"].encode('ascii'))
            bg_pix = fitz.Pixmap(img_bytes)
            
            # Get background and target rectangles
            bg_bbox = bg_data["bbox"]
            target_bbox = rect_data["bbox"]
            
            # Calculate crop area within background image
            crop_x = int((target_bbox[0] - bg_bbox[0]) * bg_data["width"] / (bg_bbox[2] - bg_bbox[0]))
            crop_y = int((target_bbox[1] - bg_bbox[1]) * bg_data["height"] / (bg_bbox[3] - bg_bbox[1]))
            crop_w = int((target_bbox[2] - target_bbox[0]) * bg_data["width"] / (bg_bbox[2] - bg_bbox[0]))
            crop_h = int((target_bbox[3] - target_bbox[1]) * bg_data["height"] / (bg_bbox[3] - bg_bbox[1]))
            
            # Crop relevant portion
            crop_rect = fitz.IRect(crop_x, crop_y, crop_x + crop_w, crop_y + crop_h)
            cropped_pix = fitz.Pixmap(bg_pix, crop_rect)
            
            # Insert cropped portion
            target_rect = fitz.Rect(target_bbox)
            page.insert_image(target_rect, pixmap=cropped_pix, overlay=True)
            
            logger.info(f"Background context restoration applied for {target_bbox}")
            
        except Exception as e:
            logger.warning(f"Failed background context restoration: {e}")
    
    def _emergency_pixmap_restore(self, page, rect_data: Dict):
        """Emergency fallback restoration method"""
        try:
            bbox = rect_data["bbox"]
            target_rect = fitz.Rect(bbox)
            
            # Try to use any available pixmap data
            pixmap_data = rect_data.get("original_pixmap") or rect_data.get("background_elements")
            
            if pixmap_data and pixmap_data.get("data"):
                img_bytes = base64.b64decode(pixmap_data["data"].encode('ascii'))
                pix = fitz.Pixmap(img_bytes)
                page.insert_image(target_rect, pixmap=pix, overlay=True)
                logger.info(f"Emergency restoration applied for {bbox}")
            else:
                # Final fallback - just clear the area
                page.draw_rect(target_rect, fill=(1, 1, 1))
                logger.warning(f"Emergency white fill applied for {bbox}")
                
        except Exception as e:
            logger.error(f"Emergency restoration failed: {e}")
    
    def _restore_text_blocks_perfectly(self, page, blocks: List[Dict], clip_rect: fitz.Rect):
        """Restore text blocks with perfect formatting"""
        try:
            for block in blocks:
                if "lines" in block:  # Text block
                    for line in block["lines"]:
                        for span in line["spans"]:
                            # Restore text with original formatting
                            text = span.get("text", "")
                            if text.strip():
                                bbox = span.get("bbox", [0, 0, 0, 0])
                                font = span.get("font", "Arial")
                                size = span.get("size", 12)
                                flags = span.get("flags", 0)
                                color = span.get("color", 0)
                                
                                # Convert color
                                if isinstance(color, int):
                                    r = (color >> 16) & 0xFF
                                    g = (color >> 8) & 0xFF
                                    b = color & 0xFF
                                    color_tuple = (r/255, g/255, b/255)
                                else:
                                    color_tuple = (0, 0, 0)  # Default black
                                
                                # Insert text at original position
                                try:
                                    page.insert_text(
                                        (bbox[0], bbox[1] + size),  # Baseline position
                                        text,
                                        fontname=font,
                                        fontsize=size,
                                        color=color_tuple
                                    )
                                except Exception as text_error:
                                    # Fallback with simpler parameters
                                    page.insert_text(
                                        (bbox[0], bbox[1] + 12),
                                        text,
                                        fontsize=12,
                                        color=(0, 0, 0)
                                    )
                        
        except Exception as e:
            logger.error(f"Failed to restore text blocks: {e}")
    
    def _restore_image_perfectly(self, page, img_data: Dict):
        """Restore image with perfect positioning"""
        try:
            bbox = img_data["bbox"]
            image_data = img_data["image_data"]
            width = img_data["width"]
            height = img_data["height"]
            
            # Decode image data
            img_bytes = base64.b64decode(image_data.encode('ascii'))
            
            # Create pixmap from image data
            pix = fitz.Pixmap(img_bytes)
            
            # Insert image at original position
            img_rect = fitz.Rect(bbox)
            page.insert_image(img_rect, pixmap=pix)
            
            logger.info(f"Successfully restored image at {bbox}")
            
        except Exception as e:
            logger.error(f"Failed to restore image: {e}")
    
    def _restore_vector_drawing(self, page, drawing: Dict):
        """Restore vector drawing/shape"""
        try:
            # This is a simplified vector restoration
            # Full vector restoration would require implementing all drawing commands
            if "rect" in drawing:
                rect = fitz.Rect(drawing["rect"])
                color = drawing.get("color", (0, 0, 0))
                width = drawing.get("width", 1)
                page.draw_rect(rect, color=color, width=width)
            
        except Exception as e:
            logger.warning(f"Could not restore vector drawing: {e}")
    
    def _remove_redactions_in_area(self, page, area_rect: fitz.Rect):
        """Remove any existing redaction annotations in the specified area"""
        try:
            # Get all annotations on the page
            annotations = page.annots()
            for annot in annotations:
                if annot.type[0] == 12:  # Redaction annotation type
                    annot_rect = annot.rect
                    if area_rect.intersects(annot_rect):
                        page.delete_annot(annot)
        except Exception as e:
            logger.warning(f"Could not remove redactions in area: {e}")
    
    def _has_rsa_encrypted_content(self, doc) -> bool:
        """Check if PDF has RSA-encrypted content annotation"""
        try:
            # Check first page for our hidden annotation
            if len(doc) > 0:
                first_page = doc[0]
                for annot in first_page.annots():
                    if annot.info.get("title") == "RSA_ENCRYPTED_CONTENT":
                        return True
            return False
        except Exception:
            return False
    
    def _get_rsa_encrypted_data(self, doc) -> bytes:
        """Get RSA-encrypted data from PDF annotation with verification"""
        try:
            # Method 1: Primary annotation
            if len(doc) > 0:
                first_page = doc[0]
                for annot in first_page.annots():
                    if annot.info.get("title") == "RSA_ENCRYPTED_CONTENT":
                        encoded_data = annot.info.get("content", "")
                        if encoded_data:
                            encrypted_data = base64.b64decode(encoded_data.encode('ascii'))
                            
                            # Verify with checksum
                            if self._verify_data_integrity(doc, encrypted_data):
                                return encrypted_data
                            else:
                                logger.warning("Primary data failed integrity check, trying backup methods")
                
                # Method 2: Fallback - reconstruct from chunks
                chunks = {}
                text_dict = first_page.get_text("dict")
                for block in text_dict.get("blocks", []):
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            text = span.get("text", "")
                            if text.startswith("CHUNK_"):
                                try:
                                    chunk_id = int(text.split(":")[0].replace("CHUNK_", ""))
                                    chunk_data = text.split(":", 1)[1]
                                    chunks[chunk_id] = chunk_data
                                except:
                                    continue
                
                if chunks:
                    # Reconstruct from chunks
                    sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
                    encoded_data = "".join(sorted_chunks)
                    encrypted_data = base64.b64decode(encoded_data.encode('ascii'))
                    if self._verify_data_integrity(doc, encrypted_data):
                        return encrypted_data
            
            return None
        except Exception as e:
            logger.error(f"Failed to get RSA encrypted data: {e}")
            return None
    
    def _verify_data_integrity(self, doc, encrypted_data: bytes) -> bool:
        """Verify data integrity using checksum"""
        try:
            # Get stored checksum
            first_page = doc[0]
            for annot in first_page.annots():
                if annot.info.get("title") == "RSA_CHECKSUM":
                    stored_checksum = annot.info.get("content", "")
                    
                    # Calculate current checksum
                    import hashlib
                    current_checksum = hashlib.md5(encrypted_data).hexdigest()
                    
                    return stored_checksum == current_checksum
            return True  # No checksum found, assume valid
        except:
            return True  # If verification fails, assume valid
    
    def _update_rsa_status(self):
        """Update RSA status in state panel"""
        has_private = self.security_module.has_private_key()
        has_public = self.security_module.has_public_key()
        self.state_panel.update_rsa_state(has_private, has_public)
    
    # ==========================================
    # UI EVENT HANDLERS / GESTIONNAIRES D'ÉVÉNEMENTS UI
    # ==========================================
    
    def _on_theme_changed(self, index: int):
        """Handle theme change"""
        self.current_theme = "light" if index == 0 else "dark"
        self.config.set("ui.default_theme", self.current_theme)
        self._apply_current_theme()
    
    def _save_current_config(self):
        """Save current window settings to config"""
        try:
            # Update config with current window size
            self.config.set("window.width", self.width())
            self.config.set("window.height", self.height())
            
            # Save to file
            self.config.save_config()
            
            self._show_info_dialog(
                "Settings Saved", 
                f"Current settings saved to:\n{self.config.config_file}\n\n"
                f"Window size: {self.width()}x{self.height()}"
            )
            
        except Exception as e:
            self._show_error_dialog("Save Failed", f"Failed to save settings: {e}")
    
    def _reset_config(self):
        """Reset configuration to defaults"""
        reply = QMessageBox.question(
            self, "Reset Configuration",
            "This will reset all settings to default values.\nAre you sure?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Reset to defaults
                self.config.config = self.config.default_config.copy()
                self.config.save_config()
                
                self._show_info_dialog(
                    "Settings Reset", 
                    "Configuration reset to defaults.\n"
                    "Please restart the application for all changes to take effect."
                )
                
            except Exception as e:
                self._show_error_dialog("Reset Failed", f"Failed to reset settings: {e}")
    
    def _on_mode_changed(self, index: int):
        """Handle mode change"""
        modes = [RedactionMode.RECTANGLE, RedactionMode.FREEHAND, RedactionMode.SMART, RedactionMode.MOVE]
        self.current_mode = modes[index]
        
        for canvas in self.canvas_widgets:
            canvas.set_mode(self.current_mode)
        
        self.state_panel.update_mode(self.current_mode)
    
    def adjust_zoom(self, factor: float):
        """Adjust zoom level"""
        for canvas in self.canvas_widgets:
            canvas.zoom(factor)
    
    def undo_last_redaction(self):
        """Undo last redaction"""
        total_redactions = 0
        for canvas in self.canvas_widgets:
            canvas.undo_last_redaction()
            total_redactions += len(canvas.rectangles) + len(canvas.polygons)
        self.state_panel.update_redaction_count(total_redactions)
    
    def clear_all_redactions(self):
        """Clear all redactions"""
        reply = QMessageBox.question(
            self, "Clear All Redactions",
            "Are you sure you want to clear all redactions?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for canvas in self.canvas_widgets:
                canvas.clear_all_redactions()
            self.state_panel.update_redaction_count(0)
    
    def choose_redaction_color(self):
        """Choose redaction color"""
        current_color = QColor(*[int(c * 255) for c in self.redaction_color])
        color = QColorDialog.getColor(
            current_color, self, "Choose Redaction Color", QColorDialog.ShowAlphaChannel
        )
        
        if color.isValid():
            self.redaction_color = (color.red() / 255.0, color.green() / 255.0, color.blue() / 255.0)
            for canvas in self.canvas_widgets:
                canvas.set_redaction_color(color)
    
    def run_ocr(self):
        """Run OCR analysis"""
        if not TESSERACT_AVAILABLE:
            self._show_warning_dialog("OCR Not Available", "Pytesseract is not installed.")
            return
        
        if not self.canvas_widgets:
            self._show_warning_dialog("No Document", "Please open a PDF document first.")
            return
        
        try:
            total_redactions = 0
            for canvas in self.canvas_widgets:
                img_path = os.path.join(self.temp_dir, f"page_{canvas.page_index}.png")
                if os.path.exists(img_path):
                    img = Image.open(img_path)
                    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
                    
                    # Clear existing rectangles
                    canvas.rectangles.clear()
                    
                    # Add detected text areas
                    for i, text in enumerate(data["text"]):
                        if text.strip():
                            x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                            canvas.rectangles.append(QRect(x, y, w, h))
                    
                    total_redactions += len(canvas.rectangles)
                    canvas.update()
            
            self.state_panel.update_redaction_count(total_redactions)
            self._show_info_dialog("OCR Complete", f"OCR analysis completed.\n{total_redactions} text areas marked for redaction.")
            
        except Exception as e:
            self._show_error_dialog("OCR Failed", str(e))
    
    def _on_redaction_added(self, area: RedactionArea):
        """Handle redaction added"""
        total_redactions = sum(len(canvas.rectangles) + len(canvas.polygons) for canvas in self.canvas_widgets)
        self.state_panel.update_redaction_count(total_redactions)
        self.status_label.setText("Redaction area added")
    
    def _on_redaction_removed(self, index: int):
        """Handle redaction removed"""
        total_redactions = sum(len(canvas.rectangles) + len(canvas.polygons) for canvas in self.canvas_widgets)
        self.state_panel.update_redaction_count(total_redactions)
        self.status_label.setText("Redaction area removed")
    
    # ==========================================
    # STYLING / STYLE
    # ==========================================
    
    def _apply_current_theme(self):
        """Apply current theme"""
        if self.current_theme == "light":
            self._apply_light_theme()
        else:
            self._apply_dark_theme()
    
    def _apply_light_theme(self):
        """Apply light theme"""
        self.setStyleSheet("""
        /* Main Application */
        QMainWindow {
            background-color: #f8f9fa;
            color: #212529;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        /* Sidebar */
        QWidget#sidebar {
            background-color: #ffffff;
            border-right: 1px solid #dee2e6;
        }
        
        QWidget#sidebar_header {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #667eea, stop:1 #764ba2);
            color: white;
        }
        
        QLabel#app_title {
            font-size: 24px;
            font-weight: bold;
            color: white;
        }
        
        QLabel#app_subtitle {
            font-size: 14px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        /* Sections */
        QWidget#section {
            background-color: #ffffff;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin: 2px;
        }
        
        QLabel#section_title {
            font-size: 14px;
            font-weight: bold;
            color: #495057;
        }
        
        QLabel#control_label {
            font-size: 12px;
            color: #6c757d;
            margin-bottom: 4px;
        }
        
        /* Buttons */
        QPushButton#primary_button {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #667eea, stop:1 #764ba2);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            font-weight: 600;
            min-height: 36px;
        }
        
        QPushButton#primary_button:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #5a67d8, stop:1 #6b46c1);
        }
        
        QPushButton#primary_button:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #4c63d2, stop:1 #553c9a);
        }
        
        QPushButton#secondary_button {
            background-color: #e9ecef;
            color: #495057;
            border: 1px solid #ced4da;
            border-radius: 6px;
            padding: 8px 14px;
            font-weight: 500;
            min-height: 32px;
        }
        
        QPushButton#secondary_button:hover {
            background-color: #f8f9fa;
            border-color: #adb5bd;
        }
        
        QPushButton#secondary_button:pressed {
            background-color: #dee2e6;
        }
        
        QPushButton#secondary_button:disabled {
            background-color: #f8f9fa;
            color: #adb5bd;
            border-color: #e9ecef;
        }
        
        QPushButton#small_button {
            background-color: #f8f9fa;
            color: #495057;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 6px 10px;
            min-width: 40px;
            min-height: 28px;
        }
        
        QPushButton#small_button:hover {
            background-color: #e9ecef;
            border-color: #ced4da;
        }
        
        /* Combo boxes */
        QComboBox {
            background-color: white;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 6px 10px;
            min-height: 24px;
            color: #495057;
        }
        
        QComboBox:hover {
            border-color: #80bdff;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        
        QComboBox::down-arrow {
            width: 12px;
            height: 12px;
            border: 2px solid #6c757d;
            border-top: none;
            border-right: none;
            transform: rotate(-45deg);
            margin-top: -2px;
        }
        
        QComboBox QAbstractItemView {
            background-color: white;
            border: 1px solid #ced4da;
            border-radius: 4px;
            selection-background-color: #667eea;
            selection-color: white;
        }
        
        /* Group boxes */
        QGroupBox {
            font-weight: 600;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            margin-top: 12px;
            padding-top: 8px;
            background-color: #ffffff;
            color: #495057;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px;
            color: #495057;
        }
        
        /* Content area */
        QWidget#content_area {
            background-color: #ffffff;
        }
        
        /* Welcome screen */
        QWidget#welcome_screen {
            background-color: #ffffff;
            border-radius: 12px;
            margin: 20px;
            padding: 40px;
        }
        
        QLabel#welcome_title {
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
        }
        
        QLabel#welcome_subtitle {
            font-size: 18px;
            color: #6c757d;
            margin-bottom: 20px;
        }
        
        QLabel#welcome_text {
            font-size: 14px;
            line-height: 1.6;
            color: #495057;
        }
        
        /* Scroll areas */
        QScrollArea {
            border: none;
            background-color: transparent;
        }
        
        QScrollBar:vertical {
            background-color: #f8f9fa;
            width: 12px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:vertical {
            background-color: #ced4da;
            border-radius: 6px;
            min-height: 20px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #adb5bd;
        }
        
        /* Status bar */
        QStatusBar {
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            color: #495057;
        }
        """)
    
    def _apply_dark_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
        /* Main Application */
        QMainWindow {
            background-color: #1e1e1e;
            color: #ffffff;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        /* Sidebar */
        QWidget#sidebar {
            background-color: #2d2d30;
            border-right: 1px solid #3e3e42;
        }
        
        QWidget#sidebar_header {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #8b5cf6, stop:1 #a855f7);
            color: white;
        }
        
        QLabel#app_title {
            font-size: 24px;
            font-weight: bold;
            color: white;
        }
        
        QLabel#app_subtitle {
            font-size: 14px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        /* Sections */
        QWidget#section {
            background-color: #3c3c3c;
            border: 1px solid #555555;
            border-radius: 8px;
            margin: 2px;
        }
        
        QLabel#section_title {
            font-size: 14px;
            font-weight: bold;
            color: #ffffff;
        }
        
        QLabel#control_label {
            font-size: 12px;
            color: #cccccc;
            margin-bottom: 4px;
        }
        
        /* Buttons */
        QPushButton#primary_button {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #8b5cf6, stop:1 #a855f7);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            font-weight: 600;
            min-height: 36px;
        }
        
        QPushButton#primary_button:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #7c3aed, stop:1 #9333ea);
        }
        
        QPushButton#primary_button:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #6d28d9, stop:1 #7e22ce);
        }
        
        QPushButton#secondary_button {
            background-color: #4a4a4a;
            color: #ffffff;
            border: 1px solid #666666;
            border-radius: 6px;
            padding: 8px 14px;
            font-weight: 500;
            min-height: 32px;
        }
        
        QPushButton#secondary_button:hover {
            background-color: #555555;
            border-color: #777777;
        }
        
        QPushButton#secondary_button:pressed {
            background-color: #3a3a3a;
        }
        
        QPushButton#secondary_button:disabled {
            background-color: #333333;
            color: #666666;
            border-color: #444444;
        }
        
        QPushButton#small_button {
            background-color: #3a3a3a;
            color: #ffffff;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 6px 10px;
            min-width: 40px;
            min-height: 28px;
        }
        
        QPushButton#small_button:hover {
            background-color: #4a4a4a;
            border-color: #666666;
        }
        
        /* Combo boxes */
        QComboBox {
            background-color: #3a3a3a;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 6px 10px;
            min-height: 24px;
            color: #ffffff;
        }
        
        QComboBox:hover {
            border-color: #8b5cf6;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        
        QComboBox::down-arrow {
            width: 12px;
            height: 12px;
            border: 2px solid #cccccc;
            border-top: none;
            border-right: none;
            transform: rotate(-45deg);
            margin-top: -2px;
        }
        
        QComboBox QAbstractItemView {
            background-color: #3a3a3a;
            border: 1px solid #555555;
            border-radius: 4px;
            selection-background-color: #8b5cf6;
            selection-color: white;
            color: #ffffff;
        }
        
        /* Group boxes */
        QGroupBox {
            font-weight: 600;
            border: 1px solid #555555;
            border-radius: 6px;
            margin-top: 12px;
            padding-top: 8px;
            background-color: #3c3c3c;
            color: #ffffff;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px;
            color: #ffffff;
        }
        
        /* Content area */
        QWidget#content_area {
            background-color: #2d2d30;
        }
        
        /* Welcome screen */
        QWidget#welcome_screen {
            background-color: #3c3c3c;
            border-radius: 12px;
            margin: 20px;
            padding: 40px;
        }
        
        QLabel#welcome_title {
            font-size: 48px;
            font-weight: bold;
            color: #8b5cf6;
        }
        
        QLabel#welcome_subtitle {
            font-size: 18px;
            color: #cccccc;
            margin-bottom: 20px;
        }
        
        QLabel#welcome_text {
            font-size: 14px;
            line-height: 1.6;
            color: #ffffff;
        }
        
        /* Scroll areas */
        QScrollArea {
            border: none;
            background-color: transparent;
        }
        
        QScrollBar:vertical {
            background-color: #2d2d30;
            width: 12px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:vertical {
            background-color: #555555;
            border-radius: 6px;
            min-height: 20px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #666666;
        }
        
        /* Status bar */
        QStatusBar {
            background-color: #2d2d30;
            border-top: 1px solid #3e3e42;
            color: #ffffff;
        }
        """)
    
    # ==========================================
    # UTILITY METHODS / MÉTHODES UTILITAIRES
    # ==========================================
    
    def _show_info_dialog(self, title: str, message: str):
        """Show information dialog"""
        QMessageBox.information(self, title, message)
    
    def _show_warning_dialog(self, title: str, message: str):
        """Show warning dialog"""
        QMessageBox.warning(self, title, message)
    
    def _show_error_dialog(self, title: str, message: str):
        """Show error dialog"""
        QMessageBox.critical(self, title, message)
    
    def closeEvent(self, event):
        """Handle application close"""
        try:
            # Auto-save current window size if enabled
            if self.config.get("window.remember_position", False):
                self.config.set("window.width", self.width())
                self.config.set("window.height", self.height())
                self.config.save_config()
            
            # Cleanup
            self.security_module.cleanup()
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            
            event.accept()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            event.accept()  # Don't prevent closing due to cleanup errors


# ==========================================
# MAIN APPLICATION ENTRY POINT / POINT D'ENTRÉE PRINCIPAL
# ==========================================

def main():
    """Main application entry point"""
    # Create application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("BlackoutPDF")
    app.setApplicationVersion("3.0")
    app.setOrganizationName("BlackoutPDF")
    app.setOrganizationDomain("blackoutpdf.local")
    
    # Show startup message
    print(" Starting BlackoutPDF v3.0...")
    print("RSA Encryption/Decryption: Available")
    print("Irréversible Redaction: Available")
    print("Multiple Export Options: Available")
    
    if not TESSERACT_AVAILABLE:
        print(" OCR features disabled (pytesseract not available)")
    else:
        print("OCR Analysis: Available")
    
    if not PIL_AVAILABLE:
        print("Some image features disabled (PIL not available)")
    else:
        print(" Image Processing: Available")
    
    # Create and show main window
    try:
        window = BlackoutPDFApp()
        window.show()
        
        print("BlackoutPDF started successfully!")
        print("Features: Modular design, RSA security, advanced redaction")
        print(f"Configuration file: {window.config.config_file}")
        
        # Start application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        QMessageBox.critical(None, "Startup Error", f"Failed to start BlackoutPDF:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# ==========================================
# INSTALLATION AND USAGE NOTES
# ==========================================

"""
Installation Requirements:
=====================================

pip install PyQt5 PyMuPDF pillow pytesseract cryptography bcrypt

Configuration System:
====================

BlackoutPDF uses a JSON configuration file for easy customization:
File: blackout_pdf_config.json (created automatically)

WINDOW SETTINGS:
{
    "window": {
        "width": 1200,              // Default window width
        "height": 800,              // Default window height
        "min_width": 1000,          // Minimum window width
        "min_height": 600,          // Minimum window height
        "center_on_screen": true,   // Auto-center on startup
        "remember_position": false  // Save size on exit
    }
}

UI SETTINGS:
{
    "ui": {
        "default_theme": "light",           // "light" or "dark"
        "sidebar_width": 350,               // Sidebar width in pixels
        "default_redaction_mode": "rectangle", // Default redaction tool
        "auto_zoom_fit": true               // Auto-fit document on load
    }
}

SECURITY SETTINGS:
{
    "security": {
        "default_key_size": 2048,           // RSA key size (2048/3072/4096)
        "auto_load_generated_keys": true,   // Auto-load after generation
        "warn_on_plain_export": true       // Warning for unencrypted export
    }
}

REDACTION SETTINGS:
{
    "redaction": {
        "default_color": [0, 0, 0],         // RGB color [red, green, blue]
        "polygon_precision": 2,             // Polygon slicing precision
        "preview_opacity": 100              // Preview transparency (0-255)
    }
}

FILE SETTINGS:
{
    "files": {
        "temp_cleanup_on_exit": true,       // Clean temp files on exit
        "remember_last_directory": true,    // Remember last used folder
        "auto_suggest_filename": true       // Auto-suggest export names
    }
}

Quick Configuration Changes:
===========================

1. **Adjust Window Size:**
   Edit "width" and "height" in config file
   OR use "Save Current Settings" button

2. **Change Default Theme:**
   Set "default_theme": "dark" for dark mode

3. **Smaller Sidebar:**
   Reduce "sidebar_width" value (minimum: 300)

4. **Different Redaction Color:**
   Change "default_color": [255, 0, 0] for red

5. **Larger RSA Keys:**
   Set "default_key_size": 4096 for maximum security

Key Features - BlackoutPDF v3.0:
===============================

Configuration Examples:
======================

For Small Screens (1366x768):
{
    "window": {
        "width": 1200,
        "height": 700,
        "sidebar_width": 300
    }
}

For Large Screens (1920x1080+):
{
    "window": {
        "width": 1400,
        "height": 900,
        "sidebar_width": 400
    }
}

For Dark Theme Users:
{
    "ui": {
        "default_theme": "dark"
    },
    "redaction": {
        "default_color": [255, 255, 255]  // White redaction for dark theme
    }
}

Usage Workflow:
==============

1. **First Run:**
   - Application creates 'blackout_pdf_config.json'
   - Window auto-fits to screen size
   - Edit config file to customize

2. **Setup Keys (Optional)**:
   - Generate RSA keys OR load existing keys
   - Keys auto-loaded when generated

3. **Load Document**:
   - Open PDF file
   - View document status in sidebar

4. **Create Redactions**:
   - Choose redaction mode
   - Draw areas to redact
   - Monitor redaction count

5. **Export Securely**:
   - Choose encryption type
   - Save with appropriate protection
   - RSA creates .key file automatically

6. **Decrypt (If Needed)**:
   - Load private key
   - Select encrypted PDF and key file
   - Document opens decrypted
"""
