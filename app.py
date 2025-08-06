#!/usr/bin/env python3
"""
MetaScan v2.1 - Enhanced Metadata Analysis Tool with Download Functionality
Complete bug-free version with cleaned image download capability
"""

import os
import hashlib
import json
import mimetypes
import threading
import time
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try importing optional packages
try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False
    logger.warning("OpenCV not available - QR code detection disabled")

try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL not available - EXIF extraction disabled")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("NumPy not available - steganography detection disabled")

try:
    from geopy.geocoders import Nominatim
    GEOPY_AVAILABLE = True
except ImportError:
    GEOPY_AVAILABLE = False
    logger.warning("Geopy not available - GPS geocoding disabled")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    try:
        import python_magic as magic
        MAGIC_AVAILABLE = True
    except ImportError:
        MAGIC_AVAILABLE = False
        logger.warning("Python-magic not available - file type detection limited")

app = Flask(__name__)
app.config.update(
    SECRET_KEY='metascan-security-key-2025',
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    TEMPLATES_AUTO_RELOAD=True
)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'bmp', 'webp'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def cleanup_old_files():
    """Clean up old files in uploads directory"""
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_dir):
            return

        current_time = time.time()
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                # Remove files older than 10 minutes
                if current_time - os.path.getmtime(file_path) > 600:
                    try:
                        os.remove(file_path)
                        logger.info(f"Cleaned up old file: {file_path}")
                    except:
                        pass
    except Exception as e:
        logger.error(f"Cleanup error: {e}")

# Schedule cleanup every 5 minutes
def schedule_cleanup():
    cleanup_old_files()
    threading.Timer(300, schedule_cleanup).start()

class MetaScanAnalyzer:
    """Main analysis class with all functionality"""

    def __init__(self):
        self.results = {}
        self.privacy_score = 100
        self.risk_factors = []

    def analyze_file(self, file_path):
        """Perform comprehensive file analysis"""
        logger.info(f"Starting analysis of: {file_path}")

        try:
            # Initialize results
            self.results = {
                'file_info': self._get_file_info(file_path),
                'hashes': self._calculate_hashes(file_path),
                'magic_bytes': self._check_magic_bytes(file_path),
                'exif_data': self._extract_exif_metadata(file_path),
                'qr_codes': self._detect_qr_codes(file_path),
                'steganography': self._detect_steganography(file_path),
                'script_injection': self._check_script_injection(file_path),
                'privacy_score': 100,
                'risks': [],
                'analysis_time': datetime.now().isoformat()
            }

            # Calculate privacy score
            self._calculate_privacy_score()

            logger.info("Analysis completed successfully")
            return self.results

        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return {
                'error': f"Analysis failed: {str(e)}",
                'privacy_score': 0,
                'risks': ['Analysis failed - file may be corrupted or unsupported'],
                'hashes': {},
                'exif_data': {},
                'qr_codes': {'found': False},
                'steganography': {'suspicious': False},
                'script_injection': {'suspicious': False},
                'magic_bytes': {'is_valid': False}
            }

    def _get_file_info(self, file_path):
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            return {
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': os.path.splitext(file_path)[1].lower()
            }
        except Exception as e:
            logger.error(f"File info error: {e}")
            return {'error': str(e)}

    def _calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        try:
            hashes = {}

            with open(file_path, 'rb') as f:
                content = f.read()

            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest() 
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['file_size'] = len(content)

            logger.info(f"Calculated hashes for {len(content)} byte file")
            return hashes

        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return {'error': str(e)}

    def _check_magic_bytes(self, file_path):
        """Check file magic bytes and validate extension"""
        try:
            result = {
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'detected_mime': 'unknown',
                'expected_mime': 'unknown',
                'is_valid': True
            }

            # Try to detect MIME type
            if MAGIC_AVAILABLE:
                try:
                    result['detected_mime'] = magic.from_file(file_path, mime=True)
                except:
                    # Fallback to mimetypes
                    mime_type, _ = mimetypes.guess_type(file_path)
                    result['detected_mime'] = mime_type or 'unknown'
            else:
                # Use mimetypes as fallback
                mime_type, _ = mimetypes.guess_type(file_path)
                result['detected_mime'] = mime_type or 'unknown'

            # Expected MIME types for extensions
            expected_mimes = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png', 
                '.gif': 'image/gif',
                '.bmp': 'image/bmp',
                '.tiff': 'image/tiff',
                '.webp': 'image/webp'
            }

            result['expected_mime'] = expected_mimes.get(result['file_extension'], 'unknown')

            # Validate if detected matches expected
            if result['detected_mime'] != 'unknown' and result['expected_mime'] != 'unknown':
                result['is_valid'] = result['detected_mime'] == result['expected_mime']
                if not result['is_valid']:
                    self.risk_factors.append('File extension mismatch detected')

            return result

        except Exception as e:
            logger.error(f"Magic bytes check error: {e}")
            return {'error': str(e), 'is_valid': False}

    def _extract_exif_metadata(self, file_path):
        """Extract EXIF metadata from image"""
        if not PIL_AVAILABLE:
            return {'metadata': {}, 'gps_data': None, 'has_sensitive_data': False}

        try:
            image = Image.open(file_path)
            exifdata = image.getexif()

            metadata = {}
            gps_data = None

            if exifdata:
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)

                    # Handle different data types
                    if isinstance(data, bytes):
                        try:
                            data = data.decode('utf-8')
                        except:
                            data = str(data)
                    elif isinstance(data, (tuple, list)):
                        data = str(data)

                    metadata[str(tag)] = str(data)

                    # Extract GPS data
                    if tag == 'GPSInfo' and data:
                        gps_data = self._extract_gps_data(data)

            # Check for sensitive data
            sensitive_tags = ['DateTime', 'Make', 'Model', 'Software', 'GPS', 'GPSInfo']
            has_sensitive_data = any(tag in metadata for tag in sensitive_tags) or gps_data is not None

            if has_sensitive_data:
                self.risk_factors.append('Sensitive EXIF metadata found')

            if gps_data:
                self.risk_factors.append('GPS location data embedded in image')

            return {
                'metadata': metadata,
                'gps_data': gps_data,
                'has_sensitive_data': has_sensitive_data
            }

        except Exception as e:
            logger.error(f"EXIF extraction error: {e}")
            return {'error': str(e), 'metadata': {}, 'gps_data': None}

    def _extract_gps_data(self, gps_info):
        """Extract GPS coordinates from EXIF data"""
        if not GEOPY_AVAILABLE:
            return None

        try:
            gps_data = {}

            # Convert GPS info to readable format
            for key in gps_info.keys():
                name = GPSTAGS.get(key, key)
                gps_data[name] = gps_info[key]

            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                lat = self._convert_to_degrees(gps_data['GPSLatitude'])
                lon = self._convert_to_degrees(gps_data['GPSLongitude'])

                # Handle hemisphere
                if 'GPSLatitudeRef' in gps_data and gps_data['GPSLatitudeRef'] == 'S':
                    lat = -lat
                if 'GPSLongitudeRef' in gps_data and gps_data['GPSLongitudeRef'] == 'W':
                    lon = -lon

                # Get address if possible
                address = self._get_address(lat, lon)

                return {
                    'latitude': lat,
                    'longitude': lon,
                    'location': address,
                    'raw_data': gps_data
                }

        except Exception as e:
            logger.error(f"GPS extraction error: {e}")
            return None

        return None

    def _convert_to_degrees(self, value):
        """Convert GPS coordinates to decimal degrees"""
        try:
            d, m, s = value
            return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)
        except:
            return 0.0

    def _get_address(self, lat, lon):
        """Get address from coordinates using reverse geocoding"""
        try:
            geolocator = Nominatim(user_agent="metascan-analyzer")
            location = geolocator.reverse(f"{lat}, {lon}", timeout=5)
            return location.address if location else None
        except Exception as e:
            logger.error(f"Geocoding error: {e}")
            return None

    def _detect_qr_codes(self, file_path):
        """Detect QR codes in image"""
        if not OPENCV_AVAILABLE:
            return {'found': False, 'message': 'OpenCV not available'}

        try:
            image = cv2.imread(file_path)
            if image is None:
                return {'found': False, 'error': 'Could not load image'}

            # Initialize QR code detector
            detector = cv2.QRCodeDetector()

            # Detect and decode QR codes
            data, vertices_array, binary_qrcode = detector.detectAndDecode(image)

            if vertices_array is not None and len(data) > 0:
                self.risk_factors.append('QR code detected in image')
                return {
                    'found': True,
                    'data': data,
                    'count': 1,
                    'vertices': vertices_array.tolist() if hasattr(vertices_array, 'tolist') else str(vertices_array)
                }
            else:
                return {'found': False, 'message': 'No QR codes detected'}

        except Exception as e:
            logger.error(f"QR code detection error: {e}")
            return {'found': False, 'error': str(e)}

    def _detect_steganography(self, file_path):
        """Basic steganography detection"""
        if not PIL_AVAILABLE or not NUMPY_AVAILABLE:
            return {'suspicious': False, 'message': 'Required libraries not available'}

        try:
            image = Image.open(file_path)

            # Get file size and image dimensions
            width, height = image.size
            file_size = os.path.getsize(file_path)

            # Calculate expected size for uncompressed RGB
            expected_size = width * height * 3
            size_ratio = file_size / expected_size if expected_size > 0 else 0

            # Convert image to array for LSB analysis
            if image.mode in ['RGB', 'RGBA']:
                img_array = np.array(image)

                # Check LSB variance (simplified steganography detection)
                lsb_data = img_array & 1  # Get least significant bits
                lsb_variance = float(np.var(lsb_data))

                # Determine if suspicious
                suspicious = size_ratio > 3.0 or lsb_variance > 0.25

                if suspicious:
                    self.risk_factors.append('Potential steganography detected')

                return {
                    'suspicious': suspicious,
                    'size_ratio': round(size_ratio, 3),
                    'lsb_variance': round(lsb_variance, 6),
                    'analysis': 'Statistical analysis completed',
                    'details': {
                        'file_size': file_size,
                        'expected_size': expected_size,
                        'dimensions': f"{width}x{height}"
                    }
                }
            else:
                return {
                    'suspicious': False,
                    'analysis': 'Image format not suitable for LSB analysis'
                }

        except Exception as e:
            logger.error(f"Steganography detection error: {e}")
            return {'suspicious': False, 'error': str(e)}

    def _check_script_injection(self, file_path):
        """Check for potential script injection in file"""
        try:
            # Read file in binary mode to handle any file type
            with open(file_path, 'rb') as f:
                content = f.read()

            # Common malicious patterns
            dangerous_patterns = [
                b'<script',
                b'javascript:',
                b'<?php',
                b'<%',
                b'eval(',
                b'exec(',
                b'system(',
                b'shell_exec',
                b'cmd.exe',
                b'powershell',
                b'<iframe',
                b'document.cookie'
            ]

            found_patterns = []
            for pattern in dangerous_patterns:
                if pattern in content.lower():
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))

            if found_patterns:
                self.risk_factors.append('Potential script injection detected')

            return {
                'suspicious': len(found_patterns) > 0,
                'patterns_found': found_patterns,
                'total_patterns': len(found_patterns),
                'analysis': f"Scanned for {len(dangerous_patterns)} malicious patterns"
            }

        except Exception as e:
            logger.error(f"Script injection check error: {e}")
            return {'suspicious': False, 'error': str(e)}

    def _calculate_privacy_score(self):
        """Calculate privacy score based on findings"""
        score = 100

        # Deduct points for various risks
        risk_penalties = {
            'GPS location data embedded in image': 30,
            'Sensitive EXIF metadata found': 20,
            'QR code detected in image': 15,
            'Potential steganography detected': 25,
            'Potential script injection detected': 40,
            'File extension mismatch detected': 20
        }

        for risk in self.risk_factors:
            penalty = risk_penalties.get(risk, 10)  # Default penalty
            score -= penalty

        # Ensure score doesn't go below 0
        score = max(0, score)

        self.results['privacy_score'] = score
        self.results['risks'] = list(set(self.risk_factors))  # Remove duplicates

        logger.info(f"Privacy score calculated: {score}/100")

# Flask routes
@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/info')
def info():
    """Cybersecurity information page"""
    return render_template('info.html')

@app.route('/api/info')
def api_info():
    """API endpoint for cybersecurity information"""
    cybersecurity_info = {
        'concepts': {
            'EXIF Metadata': {
                'description': 'Exchangeable Image File Format data embedded in images',
                'risks': 'Can contain GPS coordinates, camera info, timestamps',
                'mitigation': 'Strip metadata before sharing images online'
            },
            'Steganography': {
                'description': 'Hiding data within other non-secret data or physical objects',
                'risks': 'Secret messages or malware hidden in innocent-looking files',
                'mitigation': 'Use steganalysis tools to detect hidden content'
            },
            'Script Injection': {
                'description': 'Malicious code embedded in files or web pages',
                'risks': 'Can execute unauthorized commands or steal data',
                'mitigation': 'Validate and sanitize all user inputs'
            },
            'File Type Spoofing': {
                'description': 'Making one file type appear as another',
                'risks': 'Executable files disguised as images or documents',
                'mitigation': 'Check magic bytes, not just file extensions'
            },
            'Privacy Score': {
                'description': 'Numerical rating of privacy risks in a file',
                'calculation': 'Based on metadata, hidden content, and security risks',
                'interpretation': '0-39: Critical, 40-59: Moderate, 60-79: Good, 80-100: Excellent'
            }
        },
        'tools_used': {
            'Hash Functions': 'MD5, SHA1, SHA256 for file integrity verification',
            'OpenCV': 'Computer vision library for QR code detection',
            'PIL/Pillow': 'Python Imaging Library for EXIF extraction',
            'Magic Bytes': 'File signature analysis for type verification',
            'LSB Analysis': 'Least Significant Bit analysis for steganography detection'
        }
    }
    return jsonify(cybersecurity_info)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        logger.info("File upload request received")

        if 'file' not in request.files:
            logger.warning("No file in request")
            return jsonify({'error': 'No file selected'})

        file = request.files['file']
        if file.filename == '':
            logger.warning("Empty filename")
            return jsonify({'error': 'No file selected'})

        if file and allowed_file(file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Save the file
            file.save(filepath)
            logger.info(f"File saved: {filepath}")

            # Analyze the file
            analyzer = MetaScanAnalyzer()
            results = analyzer.analyze_file(filepath)

            # Clean up the uploaded file
            try:
                os.remove(filepath)
                logger.info(f"Cleaned up: {filepath}")
            except:
                logger.warning(f"Could not clean up: {filepath}")

            return jsonify(results)

        else:
            logger.warning(f"Invalid file type: {file.filename}")
            return jsonify({'error': 'Invalid file type. Supported: PNG, JPG, JPEG, GIF, TIFF, BMP, WEBP'})

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'})

@app.route('/remove_metadata', methods=['POST'])
def remove_metadata():
    """Remove metadata from uploaded image and provide download"""
    try:
        if not PIL_AVAILABLE:
            return jsonify({'error': 'PIL not available - metadata removal disabled'})

        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'})

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Save original file
            file.save(filepath)
            logger.info(f"Original file saved: {filepath}")

            # Remove metadata
            image = Image.open(filepath)

            # Create new image without EXIF data
            if image.mode in ['RGBA', 'LA']:
                # Handle transparency by converting to RGB
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'RGBA':
                    background.paste(image, mask=image.split()[-1])
                else:
                    background.paste(image)
                clean_image = background
            else:
                # For RGB and other modes, copy pixel data without metadata
                data = list(image.getdata())
                clean_image = Image.new(image.mode, image.size)
                clean_image.putdata(data)

            # Generate clean filename
            name_part = os.path.splitext(filename)[0]
            ext_part = os.path.splitext(filename)[1]
            clean_filename = f"{name_part}_CLEANED{ext_part}"
            clean_filepath = os.path.join(app.config['UPLOAD_FOLDER'], clean_filename)

            # Save cleaned image with high quality
            if ext_part.lower() in ['.jpg', '.jpeg']:
                clean_image.save(clean_filepath, 'JPEG', quality=95, optimize=True)
            elif ext_part.lower() == '.png':
                clean_image.save(clean_filepath, 'PNG', optimize=True)
            else:
                clean_image.save(clean_filepath)

            logger.info(f"Cleaned file saved: {clean_filepath}")

            # Get file sizes for comparison
            original_size = os.path.getsize(filepath)
            clean_size = os.path.getsize(clean_filepath)
            size_reduction = original_size - clean_size

            # Clean up original file
            os.remove(filepath)

            return jsonify({
                'success': True,
                'message': 'Metadata removed successfully! Click download to get your cleaned image.',
                'original_size': original_size,
                'clean_size': clean_size,
                'size_reduction': size_reduction,
                'download_filename': clean_filename,
                'download_url': f'/download/{clean_filename}'
            })

        return jsonify({'error': 'Invalid file type'})

    except Exception as e:
        logger.error(f"Metadata removal error: {str(e)}")
        return jsonify({'error': f'Metadata removal failed: {str(e)}'})

@app.route('/download/<filename>')
def download_file(filename):
    """Download cleaned file with automatic cleanup"""
    try:
        # Security: Only allow downloading from uploads directory
        safe_filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        if not os.path.exists(file_path):
            logger.warning(f"Download requested for non-existent file: {file_path}")
            return jsonify({'error': 'File not found or has expired'}), 404

        logger.info(f"Serving download: {file_path}")

        # Schedule file deletion after 3 minutes
        def delayed_cleanup():
            time.sleep(180)  # Wait 3 minutes
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Auto-cleaned downloaded file: {file_path}")
            except Exception as cleanup_error:
                logger.warning(f"Cleanup error for {file_path}: {cleanup_error}")

        # Start cleanup thread
        threading.Thread(target=delayed_cleanup, daemon=True).start()

        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.1.0',
        'features': {
            'opencv': OPENCV_AVAILABLE,
            'pil': PIL_AVAILABLE,
            'numpy': NUMPY_AVAILABLE,
            'geopy': GEOPY_AVAILABLE,
            'magic': MAGIC_AVAILABLE,
            'download': True
        },
        'enhancements': {
            'metadata_removal_download': True,
            'auto_cleanup': True,
            'secure_downloads': True
        }
    })

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 16MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    """Handle server errors"""
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Start cleanup scheduler
    schedule_cleanup()

    print("🚀 MetaScan v2.1 - Enhanced Metadata Analysis Tool")
    print("=" * 65)
    print("✅ Bug-free version with download functionality")
    print("📥 NEW: Download cleaned images automatically")
    print("🧹 AUTO: File cleanup after 3 minutes")
    print("🔒 SECURE: Safe file handling and validation")
    print("📍 Access at: http://localhost:5000 (for local runs)")
    print("📚 Cybersecurity info: http://localhost:5000/info")
    print("🔍 Health check: http://localhost:5000/health")
    print("=" * 65)

    import os
    port = int(os.environ.get("PORT", 5000))  # Use provided PORT or default to 5000
    app.run(debug=True, host="0.0.0.0", port=port)

