/**
 * MetaScan v2.1 - Enhanced Metadata Analysis Tool with Download Functionality
 * Complete bug-free JavaScript with cleaned image download capability
 */

console.log('🚀 MetaScan v2.1 Enhanced initializing...');

class MetaScanApp {
    constructor() {
        this.fileInput = null;
        this.uploadBox = null;
        this.analyzeBtn = null;
        this.removeMetadataBtn = null;
        this.infoBtn = null;
        this.modal = null;
        this.loadingOverlay = null;
        this.currentFile = null;

        this.init();
    }

    init() {
        console.log('🔧 Initializing enhanced MetaScan components...');

        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupApp());
        } else {
            this.setupApp();
        }
    }

    setupApp() {
        try {
            this.findElements();
            this.setupEventListeners();
            this.setupDragAndDrop();
            this.hideLoading();
            this.checkHealth();

            console.log('✅ MetaScan v2.1 Enhanced ready!');
            this.showAlert('MetaScan v2.1 Enhanced with download functionality initialized!', 'success');
        } catch (error) {
            console.error('❌ MetaScan initialization failed:', error);
            this.showAlert('Initialization failed: ' + error.message, 'error');
        }
    }

    findElements() {
        console.log('🔍 Finding DOM elements...');

        // Get all required elements
        this.fileInput = document.getElementById('fileInput');
        this.uploadBox = document.getElementById('uploadBox');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.removeMetadataBtn = document.getElementById('removeMetadataBtn');
        this.infoBtn = document.getElementById('infoBtn');
        this.modal = document.getElementById('infoModal');
        this.loadingOverlay = document.getElementById('loadingOverlay');

        // Validate elements exist
        const elements = {
            'File Input': this.fileInput,
            'Upload Box': this.uploadBox,
            'Analyze Button': this.analyzeBtn,
            'Remove Metadata Button': this.removeMetadataBtn,
            'Info Button': this.infoBtn,
            'Modal': this.modal,
            'Loading Overlay': this.loadingOverlay
        };

        let missingElements = [];
        for (const [name, element] of Object.entries(elements)) {
            if (!element) {
                missingElements.push(name);
            }
        }

        if (missingElements.length > 0) {
            throw new Error(`Missing DOM elements: ${missingElements.join(', ')}`);
        }

        console.log('✅ All DOM elements found successfully');
    }

    setupEventListeners() {
        console.log('🔗 Setting up event listeners...');

        // File input change
        this.fileInput.addEventListener('change', (e) => {
            console.log('📁 File selected via input');
            this.handleFileSelect(e);
        });

        // Upload box click
        this.uploadBox.addEventListener('click', () => {
            console.log('📤 Upload box clicked');
            this.fileInput.click();
        });

        // Analyze button
        this.analyzeBtn.addEventListener('click', () => {
            console.log('🔍 Analyze button clicked');
            this.analyzeFile();
        });

        // Remove metadata button
        this.removeMetadataBtn.addEventListener('click', () => {
            console.log('🧹 Remove metadata button clicked');
            this.removeMetadata();
        });

        // Info button
        this.infoBtn.addEventListener('click', () => {
            console.log('ℹ️ Info button clicked');
            this.showCybersecurityInfo();
        });

        // Modal close
        const closeBtn = document.getElementById('closeModal');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideModal());
        }

        // Close modal on background click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.hideModal();
            }
        });

        // Footer links
        this.setupFooterLinks();

        console.log('✅ Event listeners setup complete');
    }

    setupFooterLinks() {
        const healthCheck = document.getElementById('healthCheck');
        if (healthCheck) {
            healthCheck.addEventListener('click', (e) => {
                e.preventDefault();
                this.checkHealth();
            });
        }
    }

    setupDragAndDrop() {
        console.log('🎯 Setting up drag and drop...');

        const events = ['dragenter', 'dragover', 'dragleave', 'drop'];

        events.forEach(eventName => {
            this.uploadBox.addEventListener(eventName, this.preventDefaults, false);
            document.body.addEventListener(eventName, this.preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            this.uploadBox.addEventListener(eventName, () => this.highlight(), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.uploadBox.addEventListener(eventName, () => this.unhighlight(), false);
        });

        this.uploadBox.addEventListener('drop', (e) => this.handleDrop(e), false);

        console.log('✅ Drag and drop setup complete');
    }

    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    highlight() {
        this.uploadBox.style.borderColor = 'var(--accent-color)';
        this.uploadBox.style.background = 'linear-gradient(135deg, #0a0a0a, #2a2a2a)';
    }

    unhighlight() {
        this.uploadBox.style.borderColor = 'var(--primary-color)';
        this.uploadBox.style.background = 'var(--gradient-primary)';
    }

    handleDrop(e) {
        console.log('📥 File dropped');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            this.fileInput.files = files;
            this.handleFileSelect({ target: { files: files } });
        }
    }

    handleFileSelect(e) {
        const files = e.target.files;
        console.log('📂 File selection handler:', files ? files.length : 0, 'files');

        if (!files || files.length === 0) {
            console.log('⚠️ No files selected');
            return;
        }

        const file = files[0];
        this.currentFile = file;

        // Validate file
        if (!this.validateFile(file)) {
            return;
        }

        this.displayFileInfo(file);
        this.enableButtons();
    }

    validateFile(file) {
        const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/tiff', 'image/bmp', 'image/webp'];
        const maxSize = 16 * 1024 * 1024; // 16MB

        if (!allowedTypes.includes(file.type) && !this.hasValidExtension(file.name)) {
            this.showAlert('Invalid file type. Please select an image file.', 'error');
            return false;
        }

        if (file.size > maxSize) {
            this.showAlert('File too large. Maximum size is 16MB.', 'error');
            return false;
        }

        return true;
    }

    hasValidExtension(filename) {
        const validExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.tiff', '.bmp', '.webp'];
        const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        return validExtensions.includes(extension);
    }

    displayFileInfo(file) {
        console.log('📋 Displaying file info for:', file.name);

        const fileSize = this.formatFileSize(file.size);

        this.uploadBox.innerHTML = `
            <i class="fas fa-file-image upload-icon"></i>
            <h3>File Selected</h3>
            <p><strong>${this.escapeHtml(file.name)}</strong></p>
            <p>Size: ${fileSize} | Type: ${file.type || 'Unknown'}</p>
            <p class="file-ready">Ready for analysis</p>
        `;
    }

    enableButtons() {
        this.analyzeBtn.disabled = false;
        this.removeMetadataBtn.disabled = false;
        console.log('✅ Analysis buttons enabled');
    }

    disableButtons() {
        this.analyzeBtn.disabled = true;
        this.removeMetadataBtn.disabled = true;
        console.log('⏸️ Analysis buttons disabled');
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    async analyzeFile() {
        if (!this.currentFile) {
            this.showAlert('Please select a file first', 'warning');
            return;
        }

        console.log('🔍 Starting file analysis...');

        try {
            this.showLoading('Analyzing file...');
            this.disableButtons();

            const formData = new FormData();
            formData.append('file', this.currentFile);

            console.log('📤 Sending file to server...');

            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            console.log('📥 Server response status:', response.status);

            if (!response.ok) {
                throw new Error(`Server error: ${response.status} ${response.statusText}`);
            }

            const result = await response.json();
            console.log('📊 Analysis result:', result);

            this.hideLoading();
            this.enableButtons();

            if (result.error) {
                this.showAlert('Analysis error: ' + result.error, 'error');
                return;
            }

            this.displayResults(result);
            this.showAlert('File analysis completed successfully!', 'success');

        } catch (error) {
            console.error('❌ Analysis failed:', error);
            this.hideLoading();
            this.enableButtons();
            this.showAlert('Analysis failed: ' + error.message, 'error');
        }
    }

    async removeMetadata() {
        if (!this.currentFile) {
            this.showAlert('Please select a file first', 'warning');
            return;
        }

        console.log('🧹 Starting metadata removal...');

        try {
            this.showLoading('Removing metadata and preparing download...');
            this.disableButtons();

            const formData = new FormData();
            formData.append('file', this.currentFile);

            const response = await fetch('/remove_metadata', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.status} ${response.statusText}`);
            }

            const result = await response.json();
            console.log('🧹 Metadata removal result:', result);

            this.hideLoading();
            this.enableButtons();

            if (result.error) {
                this.showAlert('Metadata removal error: ' + result.error, 'error');
                return;
            }

            if (result.success && result.download_url) {
                const sizeReduction = result.size_reduction || 0;
                const message = `Metadata removed successfully! Size reduction: ${this.formatFileSize(sizeReduction)}`;

                // Show enhanced download alert
                this.showDownloadAlert(message, result.download_url, result.download_filename);
            } else {
                this.showAlert('Metadata removal completed but no download available', 'warning');
            }

        } catch (error) {
            console.error('❌ Metadata removal failed:', error);
            this.hideLoading();
            this.enableButtons();
            this.showAlert('Metadata removal failed: ' + error.message, 'error');
        }
    }

    showDownloadAlert(message, downloadUrl, filename) {
        console.log('📥 Showing download alert for:', filename);

        const alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) {
            // Fallback to regular alert
            this.showAlert(message + ' Download ready!', 'success');
            return;
        }

        const alert = document.createElement('div');
        alert.className = 'alert alert-success download-alert';
        alert.style.cssText = `
            background: var(--bg-card);
            border: 2px solid var(--success-color);
            border-radius: 10px;
            padding: 1.5rem;
            max-width: 450px;
            box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);
            animation: slideInRight 0.3s ease-out;
            position: relative;
        `;

        alert.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
                <i class="fas fa-check-circle" style="color: var(--success-color); font-size: 1.2rem;"></i>
                <span style="color: var(--success-color); font-weight: bold; font-family: 'Orbitron', monospace;">Metadata Removed!</span>
            </div>
            <p style="margin: 0.5rem 0; color: var(--text-secondary); font-size: 0.9rem; line-height: 1.4;">${this.escapeHtml(message)}</p>
            <div style="display: flex; gap: 1rem; margin-top: 1rem; align-items: center;">
                <button class="download-btn" style="
                    background: linear-gradient(45deg, var(--primary-color), #00cc33);
                    color: var(--bg-primary);
                    border: none;
                    padding: 0.8rem 1.3rem;
                    border-radius: 6px;
                    font-weight: bold;
                    cursor: pointer;
                    flex: 1;
                    font-size: 0.9rem;
                    font-family: 'Orbitron', monospace;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: hidden;
                ">
                    <i class="fas fa-download"></i> DOWNLOAD CLEANED IMAGE
                </button>
                <button class="close-btn" style="
                    background: none;
                    border: none;
                    color: var(--text-muted);
                    font-size: 1.8rem;
                    cursor: pointer;
                    padding: 0.5rem;
                    transition: all 0.3s ease;
                    border-radius: 4px;
                ">×</button>
            </div>
            <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.7rem; font-style: italic; text-align: center;">
                <i class="fas fa-clock"></i> File will be auto-deleted in 3 minutes for privacy
            </p>
        `;

        // Download button functionality
        const downloadBtn = alert.querySelector('.download-btn');
        downloadBtn.addEventListener('click', () => {
            this.downloadFile(downloadUrl, filename);

            // Update button state
            downloadBtn.style.opacity = '0.8';
            downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> DOWNLOADING...';
            downloadBtn.disabled = true;
            downloadBtn.style.cursor = 'not-allowed';

            // Auto-close after download
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.style.opacity = '0';
                    alert.style.transform = 'translateX(400px)';
                    setTimeout(() => alert.remove(), 300);
                }
            }, 2000);
        });

        // Close button
        const closeBtn = alert.querySelector('.close-btn');
        closeBtn.addEventListener('click', () => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(400px)';
            setTimeout(() => alert.remove(), 300);
        });

        // Hover effects
        downloadBtn.addEventListener('mouseenter', () => {
            if (!downloadBtn.disabled) {
                downloadBtn.style.transform = 'translateY(-2px)';
                downloadBtn.style.boxShadow = '0 5px 15px rgba(0, 255, 65, 0.4)';
            }
        });

        downloadBtn.addEventListener('mouseleave', () => {
            if (!downloadBtn.disabled) {
                downloadBtn.style.transform = 'translateY(0)';
                downloadBtn.style.boxShadow = 'none';
            }
        });

        closeBtn.addEventListener('mouseenter', () => {
            closeBtn.style.color = 'var(--danger-color)';
            closeBtn.style.background = 'rgba(255, 68, 68, 0.1)';
        });

        closeBtn.addEventListener('mouseleave', () => {
            closeBtn.style.color = 'var(--text-muted)';
            closeBtn.style.background = 'none';
        });

        // Auto remove after 30 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateX(400px)';
                setTimeout(() => alert.remove(), 300);
            }
        }, 30000);

        alertContainer.appendChild(alert);

        // Add shine effect to download button
        const shimmer = setInterval(() => {
            if (!downloadBtn.disabled && alert.parentNode) {
                downloadBtn.style.background = 'linear-gradient(45deg, var(--primary-color), #00cc33, var(--primary-color))';
                downloadBtn.style.backgroundSize = '200% 100%';
                downloadBtn.style.animation = 'shimmer 1.5s ease-in-out';
            } else {
                clearInterval(shimmer);
            }
        }, 3000);

        // Add shimmer animation to CSS if not already present
        if (!document.querySelector('#shimmer-style')) {
            const style = document.createElement('style');
            style.id = 'shimmer-style';
            style.textContent = `
                @keyframes shimmer {
                    0% { background-position: -200% 0; }
                    100% { background-position: 200% 0; }
                }
            `;
            document.head.appendChild(style);
        }
    }

    downloadFile(url, filename) {
        console.log(`📥 Downloading: ${filename}`);

        try {
            // Create temporary download link
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            link.style.display = 'none';

            // Add to DOM and trigger download
            document.body.appendChild(link);
            link.click();

            // Clean up
            setTimeout(() => {
                if (document.body.contains(link)) {
                    document.body.removeChild(link);
                }
            }, 100);

            console.log(`✅ Download initiated: ${filename}`);

            // Show success feedback
            setTimeout(() => {
                this.showAlert(`✅ Downloaded: ${filename}`, 'success');
            }, 500);

        } catch (error) {
            console.error('❌ Download failed:', error);
            this.showAlert('Download failed: ' + error.message, 'error');
        }
    }

    displayResults(data) {
        console.log('📊 Displaying analysis results...');

        // Show results section
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Update all result sections
        this.updatePrivacyScore(data.privacy_score || 0);
        this.updateRisks(data.risks || []);
        this.updateFileInfo(data.file_info || {});
        this.updateExifData(data.exif_data || {});
        this.updateGpsData(data.exif_data?.gps_data);
        this.updateQrData(data.qr_codes || {});
        this.updateSteganographyData(data.steganography || {});
        this.updateScriptData(data.script_injection || {});
        this.updateFileValidation(data.magic_bytes || {});
        this.updateHashData(data.hashes || {});

        console.log('✅ Results display complete');
    }

    updatePrivacyScore(score) {
        const scoreValue = document.getElementById('scoreValue');
        const scoreStatus = document.getElementById('scoreStatus');
        const scoreCircle = document.getElementById('scoreCircle');

        if (scoreValue) scoreValue.textContent = score;

        let status, color, statusClass;
        if (score >= 80) {
            status = 'EXCELLENT';
            color = 'var(--success-color)';
            statusClass = 'status-excellent';
        } else if (score >= 60) {
            status = 'GOOD';
            color = 'var(--warning-color)';
            statusClass = 'status-good';
        } else if (score >= 40) {
            status = 'MODERATE';
            color = '#ff8800';
            statusClass = 'status-moderate';
        } else {
            status = 'CRITICAL';
            color = 'var(--danger-color)';
            statusClass = 'status-critical';
        }

        if (scoreStatus) {
            scoreStatus.innerHTML = `<span class="status-text ${statusClass}">${status}</span>`;
        }

        if (scoreValue) {
            scoreValue.style.color = color;
        }

        if (scoreCircle) {
            const gradient = `conic-gradient(${color} ${score * 3.6}deg, var(--border-color) ${score * 3.6}deg)`;
            scoreCircle.style.background = gradient;
        }

        console.log(`📊 Privacy score updated: ${score}/100 (${status})`);
    }

    updateRisks(risks) {
        const container = document.getElementById('risksContainer');
        if (!container) return;

        if (!risks || risks.length === 0) {
            container.innerHTML = `
                <div class="risk-item safe">
                    <i class="fas fa-shield-alt"></i>
                    <span>No significant privacy risks detected</span>
                </div>
            `;
            return;
        }

        container.innerHTML = risks.map(risk => `
            <div class="risk-item">
                <i class="fas fa-exclamation-triangle"></i>
                <span>${this.escapeHtml(risk)}</span>
            </div>
        `).join('');

        console.log(`⚠️ Risks updated: ${risks.length} risks found`);
    }

    updateFileInfo(fileInfo) {
        const container = document.getElementById('fileInfo');
        if (!container) return;

        if (fileInfo.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(fileInfo.error)}</div>`;
            return;
        }

        const items = [
            ['Name', fileInfo.name],
            ['Size', fileInfo.size ? this.formatFileSize(fileInfo.size) : 'Unknown'],
            ['Extension', fileInfo.extension || 'Unknown'],
            ['Modified', fileInfo.modified ? new Date(fileInfo.modified).toLocaleString() : 'Unknown']
        ];

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');
    }

    updateExifData(exifData) {
        const container = document.getElementById('exifData');
        if (!container) return;

        if (exifData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(exifData.error)}</div>`;
            return;
        }

        if (!exifData.metadata || Object.keys(exifData.metadata).length === 0) {
            container.innerHTML = '<div class="no-data">No EXIF metadata found</div>';
            return;
        }

        const metadata = exifData.metadata;
        const entries = Object.entries(metadata).slice(0, 10);

        container.innerHTML = entries.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${this.escapeHtml(key)}:</span>
                <span class="data-value">${this.escapeHtml(this.truncateValue(String(value)))}</span>
            </div>
        `).join('');

        console.log(`📷 EXIF data updated: ${entries.length} entries`);
    }

    updateGpsData(gpsData) {
        const container = document.getElementById('gpsData');
        if (!container) return;

        if (!gpsData) {
            container.innerHTML = '<div class="no-data">No GPS data found</div>';
            return;
        }

        if (gpsData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(gpsData.error)}</div>`;
            return;
        }

        const items = [
            ['Latitude', gpsData.latitude?.toFixed(6) || 'N/A'],
            ['Longitude', gpsData.longitude?.toFixed(6) || 'N/A'],
            ['Location', gpsData.location || 'Unknown']
        ];

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');

        if (gpsData.latitude && gpsData.longitude) {
            container.innerHTML += `
                <div class="geo-warning" style="margin-top: 1rem; padding: 0.7rem; background: rgba(255,68,68,0.1); border: 1px solid var(--danger-color); border-radius: 6px; color: var(--danger-color); font-size: 0.9rem;">
                    <i class="fas fa-exclamation-triangle" style="margin-right: 0.5rem;"></i>
                    <strong>Privacy Alert:</strong> This image contains precise location data!
                </div>
            `;
        }

        console.log('🌍 GPS data updated');
    }

    updateQrData(qrData) {
        const container = document.getElementById('qrData');
        if (!container) return;

        if (qrData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(qrData.error)}</div>`;
            return;
        }

        if (!qrData.found) {
            container.innerHTML = '<div class="no-data">No QR codes detected</div>';
            return;
        }

        const items = [
            ['QR Codes Found', qrData.count || 1],
            ['Content', qrData.data || 'Unable to decode']
        ];

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');

        console.log('📱 QR code data updated');
    }

    updateSteganographyData(stegoData) {
        const container = document.getElementById('stegoData');
        if (!container) return;

        if (stegoData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(stegoData.error)}</div>`;
            return;
        }

        const suspicious = stegoData.suspicious || false;
        const analysis = stegoData.analysis || 'Analysis completed';

        const items = [
            ['Status', suspicious ? 'SUSPICIOUS' : 'CLEAN'],
            ['Analysis', analysis]
        ];

        if (stegoData.size_ratio) {
            items.push(['Size Ratio', stegoData.size_ratio.toFixed(3)]);
        }

        if (stegoData.lsb_variance) {
            items.push(['LSB Variance', stegoData.lsb_variance.toFixed(6)]);
        }

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value ${key === 'Status' ? (suspicious ? 'status-suspicious' : 'status-clean') : ''}">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');

        console.log('🕵️ Steganography data updated');
    }

    updateScriptData(scriptData) {
        const container = document.getElementById('scriptData');
        if (!container) return;

        if (scriptData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(scriptData.error)}</div>`;
            return;
        }

        const suspicious = scriptData.suspicious || false;
        const analysis = scriptData.analysis || 'Analysis completed';
        const patternsFound = scriptData.patterns_found || [];

        const items = [
            ['Status', suspicious ? 'SUSPICIOUS' : 'CLEAN'],
            ['Analysis', analysis],
            ['Patterns Found', patternsFound.length]
        ];

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value ${key === 'Status' ? (suspicious ? 'status-suspicious' : 'status-clean') : ''}">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');

        if (patternsFound.length > 0) {
            container.innerHTML += `
                <div style="margin-top: 0.5rem; padding: 0.6rem; background: rgba(255,68,68,0.1); border-radius: 5px; font-size: 0.85rem;">
                    <strong>Patterns:</strong> ${patternsFound.map(p => this.escapeHtml(p)).join(', ')}
                </div>
            `;
        }

        console.log('📜 Script injection data updated');
    }

    updateFileValidation(magicData) {
        const container = document.getElementById('fileValidation');
        if (!container) return;

        if (magicData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(magicData.error)}</div>`;
            return;
        }

        const isValid = magicData.is_valid !== false;

        const items = [
            ['Status', isValid ? 'VALID' : 'MISMATCH'],
            ['Extension', magicData.file_extension || 'Unknown'],
            ['Detected MIME', magicData.detected_mime || 'Unknown'],
            ['Expected MIME', magicData.expected_mime || 'Unknown']
        ];

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value ${key === 'Status' ? (isValid ? 'status-valid' : 'status-invalid') : ''}">${this.escapeHtml(String(value))}</span>
            </div>
        `).join('');

        console.log('✅ File validation data updated');
    }

    updateHashData(hashData) {
        const container = document.getElementById('hashData');
        if (!container) return;

        if (hashData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(hashData.error)}</div>`;
            return;
        }

        const items = [
            ['MD5', hashData.md5 || 'Not calculated'],
            ['SHA1', hashData.sha1 || 'Not calculated'], 
            ['SHA256', hashData.sha256 || 'Not calculated']
        ];

        if (hashData.file_size) {
            items.push(['File Size', this.formatFileSize(hashData.file_size)]);
        }

        container.innerHTML = items.map(([key, value]) => `
            <div class="data-item">
                <span class="data-key">${key}:</span>
                <span class="data-value hash" title="${this.escapeHtml(String(value))}">${this.escapeHtml(this.truncateValue(String(value), 30))}</span>
            </div>
        `).join('');

        console.log('🔐 Hash data updated');
    }

    truncateValue(value, maxLength = 50) {
        if (typeof value === 'string' && value.length > maxLength) {
            return value.substring(0, maxLength - 3) + '...';
        }
        return value;
    }

    async showCybersecurityInfo() {
        console.log('ℹ️ Loading cybersecurity information...');

        this.showModal();

        const modalBody = document.getElementById('modalBody');
        if (!modalBody) return;

        // Show loading
        modalBody.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>Loading cybersecurity information...</p>
            </div>
        `;

        try {
            const response = await fetch('/api/info');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            this.displayCybersecurityInfo(data);
            console.log('✅ Cybersecurity info loaded');

        } catch (error) {
            console.error('❌ Failed to load cybersecurity info:', error);
            modalBody.innerHTML = `
                <div class="error">
                    <h3>Failed to load information</h3>
                    <p>Error: ${this.escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    displayCybersecurityInfo(data) {
        const modalBody = document.getElementById('modalBody');
        if (!modalBody) return;

        let html = '<div class="concept-grid">';

        // Add concepts
        if (data.concepts) {
            for (const [name, info] of Object.entries(data.concepts)) {
                html += `
                    <div class="concept-item">
                        <h3>${this.escapeHtml(name)}</h3>
                        <p><strong>Description:</strong> ${this.escapeHtml(info.description || 'No description available')}</p>
                        ${info.risks ? `<p><strong>Risks:</strong> ${this.escapeHtml(info.risks)}</p>` : ''}
                        ${info.mitigation ? `<p><strong>Mitigation:</strong> ${this.escapeHtml(info.mitigation)}</p>` : ''}
                        ${info.calculation ? `<p><strong>Calculation:</strong> ${this.escapeHtml(info.calculation)}</p>` : ''}
                        ${info.interpretation ? `<p><strong>Interpretation:</strong> ${this.escapeHtml(info.interpretation)}</p>` : ''}
                    </div>
                `;
            }
        }

        // Add tools section
        if (data.tools_used) {
            html += `
                <div class="concept-item">
                    <h3>🛠️ Tools & Technologies</h3>
            `;

            for (const [tool, description] of Object.entries(data.tools_used)) {
                html += `<p><strong>${this.escapeHtml(tool)}:</strong> ${this.escapeHtml(description)}</p>`;
            }

            html += '</div>';
        }

        html += '</div>';
        modalBody.innerHTML = html;
    }

    showModal() {
        if (this.modal) {
            this.modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }
    }

    hideModal() {
        if (this.modal) {
            this.modal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }

    showLoading(message = 'Processing...') {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = 'flex';
            const messageElement = document.getElementById('loadingMessage');
            if (messageElement) {
                messageElement.textContent = message;
            }
        }
    }

    hideLoading() {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = 'none';
        }
    }

    showAlert(message, type = 'info') {
        console.log(`🔔 Alert (${type}): ${message}`);

        const container = document.getElementById('alertContainer');
        if (!container) {
            // Fallback to browser alert
            alert(message);
            return;
        }

        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;

        const icon = this.getAlertIcon(type);

        alert.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <span>${this.escapeHtml(message)}</span>
            <span class="alert-close">&times;</span>
        `;

        // Close button
        const closeBtn = alert.querySelector('.alert-close');
        closeBtn.addEventListener('click', () => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(400px)';
            setTimeout(() => alert.remove(), 300);
        });

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateX(400px)';
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);

        container.appendChild(alert);
    }

    getAlertIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    async checkHealth() {
        console.log('🏥 Checking system health...');

        try {
            const response = await fetch('/health');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const health = await response.json();
            console.log('🏥 Health check result:', health);

            const features = health.features || {};
            const available = Object.values(features).filter(Boolean).length;
            const total = Object.keys(features).length;

            const enhancements = health.enhancements || {};
            const downloadEnabled = enhancements.metadata_removal_download ? '✅' : '❌';

            this.showAlert(`System healthy! ${available}/${total} features available (v${health.version || 'unknown'}) ${downloadEnabled} Download enabled`, 'success');

        } catch (error) {
            console.error('❌ Health check failed:', error);
            this.showAlert(`Health check failed: ${error.message}`, 'warning');
        }
    }
}

// Initialize app when DOM is ready
let metaScanApp;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        metaScanApp = new MetaScanApp();
    });
} else {
    metaScanApp = new MetaScanApp();
}

// Global error handler
window.addEventListener('error', (e) => {
    console.error('💥 Global error:', e.error);
    if (metaScanApp) {
        metaScanApp.showAlert('An unexpected error occurred: ' + e.error.message, 'error');
    }
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (e) => {
    console.error('💥 Unhandled promise rejection:', e.reason);
    if (metaScanApp) {
        metaScanApp.showAlert('Promise rejection: ' + e.reason, 'error');
    }
});

console.log('✅ MetaScan v2.1 Enhanced script loaded successfully with download functionality!');