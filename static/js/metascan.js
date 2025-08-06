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
            <div class="upload-icon">
                <i class="fas fa-check-circle"></i>
            </div>
            <h3><strong>${this.escapeHtml(file.name)}</strong></h3>
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
            "'": '&#x27;'
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
            <div style="display: flex; align-items: center; gap: 1rem;">
                <i class="fas fa-check-circle" style="color: var(--success-color); font-size: 1.5rem;"></i>
                <div style="flex: 1;">
                    <div style="font-weight: bold; margin-bottom: 0.5rem;">${this.escapeHtml(message)}</div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">File will be auto-deleted in 3 minutes for privacy</div>
                </div>
                <button class="close-btn" style="background: none; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; padding: 0.5rem;">&times;</button>
            </div>
            <div style="margin-top: 1rem; display: flex; gap: 1rem;">
                <button class="download-btn" style="
                    background: linear-gradient(45deg, var(--primary-color), #00cc33);
                    color: var(--bg-primary);
                    border: none;
                    padding: 0.8rem 1.5rem;
                    border-radius: 5px;
                    cursor: pointer;
                    font-family: 'Orbitron', monospace;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    transition: all 0.3s ease;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                ">
                    <i class="fas fa-download"></i>
                    DOWNLOAD CLEANED IMAGE
                </button>
            </div>
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
            scoreStatus.innerHTML = `<span class="${statusClass}">${status}</span>`;
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
                    <span>No significant security risks detected</span>
                </div>
            `;
            return;
        }

        let html = '';
        risks.forEach(risk => {
            let riskClass = 'risk-item';
            let icon = 'fas fa-exclamation-triangle';

            if (risk.includes('GPS') || risk.includes('location')) {
                riskClass += '';
                icon = 'fas fa-map-marker-alt';
            } else if (risk.includes('script') || risk.includes('injection')) {
                riskClass += '';
                icon = 'fas fa-code';
            } else if (risk.includes('steganography')) {
                riskClass += '';
                icon = 'fas fa-eye-slash';
            } else if (risk.includes('QR')) {
                riskClass += ' warning';
                icon = 'fas fa-qrcode';
            }

            html += `
                <div class="${riskClass}">
                    <i class="${icon}"></i>
                    <span>${this.escapeHtml(risk)}</span>
                </div>
            `;
        });

        container.innerHTML = html;
        console.log(`⚠️ Updated ${risks.length} security risks`);
    }

    updateFileInfo(fileInfo) {
        const container = document.getElementById('fileInfoContainer');
        if (!container) return;

        if (fileInfo.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(fileInfo.error)}</div>`;
            return;
        }

        let html = '';
        const infoFields = {
            'name': 'File Name',
            'size': 'File Size',
            'modified': 'Modified Date',
            'extension': 'Extension'
        };

        for (const [key, label] of Object.entries(infoFields)) {
            if (fileInfo[key] !== undefined) {
                let value = fileInfo[key];
                if (key === 'size') {
                    value = this.formatFileSize(value);
                } else if (key === 'modified') {
                    value = new Date(value).toLocaleString();
                }

                html += `
                    <div class="data-item">
                        <div class="data-key">${label}</div>
                        <div class="data-value">${this.escapeHtml(String(value))}</div>
                    </div>
                `;
            }
        }

        container.innerHTML = html || '<div class="no-data">No file information available</div>';
    }

    updateExifData(exifData) {
        const container = document.getElementById('exifContainer');
        if (!container) return;

        if (exifData.error) {
            container.innerHTML = `<div class="error">Error: ${this.escapeHtml(exifData.error)}</div>`;
            return;
        }

        const metadata = exifData.metadata || {};

        if (Object.keys(metadata).length === 0) {
            container.innerHTML = '<div class="no-data">No EXIF metadata found</div>';
            return;
        }

        let html = '';
        for (const [key, value] of Object.entries(metadata)) {
            if (key !== 'GPSInfo') { // GPS info is shown separately
                html += `
                    <div class="data-item">
                        <div class="data-key">${this.escapeHtml(key)}</div>
                        <div class="data-value">${this.escapeHtml(String(value))}</div>
                    </div>
                `;
            }
        }

        container.innerHTML = html || '<div class="no-data">No displayable EXIF data</div>';
    }

    updateGpsData(gpsData) {
        const container = document.getElementById('gpsContainer');
        if (!container) return;

        if (!gpsData) {
            container.innerHTML = '<div class="no-data">No GPS location data found</div>';
            return;
        }

        if (gpsData.error) {
            container.innerHTML = `<div class="error">GPS Error: ${this.escapeHtml(gpsData.error)}</div>`;
            return;
        }

        let html = '';

        if (gpsData.latitude && gpsData.longitude) {
            html += `
                <div class="data-item">
                    <div class="data-key">Latitude</div>
                    <div class="data-value status-critical">${gpsData.latitude.toFixed(6)}</div>
                </div>
                <div class="data-item">
                    <div class="data-key">Longitude</div>
                    <div class="data-value status-critical">${gpsData.longitude.toFixed(6)}</div>
                </div>
            `;

            if (gpsData.location) {
                html += `
                    <div class="data-item">
                        <div class="data-key">Location</div>
                        <div class="data-value status-critical">${this.escapeHtml(gpsData.location)}</div>
                    </div>
                `;
            }
        } else {
            html = '<div class="no-data">GPS coordinates not available</div>';
        }

        container.innerHTML = html;
    }

    updateQrData(qrData) {
        const container = document.getElementById('qrContainer');
        if (!container) return;

        if (qrData.error) {
            container.innerHTML = `<div class="error">QR Error: ${this.escapeHtml(qrData.error)}</div>`;
            return;
        }

        if (!qrData.found) {
            container.innerHTML = '<div class="no-data">No QR codes detected</div>';
            return;
        }

        let html = `
            <div class="data-item">
                <div class="data-key">QR Codes Found</div>
                <div class="data-value status-suspicious">${qrData.count || 1}</div>
            </div>
        `;

        if (qrData.data) {
            html += `
                <div class="data-item">
                    <div class="data-key">QR Content</div>
                    <div class="data-value status-suspicious">${this.escapeHtml(qrData.data)}</div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    updateSteganographyData(stegoData) {
        const container = document.getElementById('steganographyContainer');
        if (!container) return;

        if (stegoData.error) {
            container.innerHTML = `<div class="error">Steganography Error: ${this.escapeHtml(stegoData.error)}</div>`;
            return;
        }

        let html = `
            <div class="data-item">
                <div class="data-key">Suspicious</div>
                <div class="data-value ${stegoData.suspicious ? 'status-suspicious' : 'status-clean'}">
                    ${stegoData.suspicious ? 'YES' : 'NO'}
                </div>
            </div>
        `;

        if (stegoData.size_ratio !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">Size Ratio</div>
                    <div class="data-value">${stegoData.size_ratio}</div>
                </div>
            `;
        }

        if (stegoData.lsb_variance !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">LSB Variance</div>
                    <div class="data-value">${stegoData.lsb_variance}</div>
                </div>
            `;
        }

        if (stegoData.analysis) {
            html += `
                <div class="data-item">
                    <div class="data-key">Analysis</div>
                    <div class="data-value">${this.escapeHtml(stegoData.analysis)}</div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    updateScriptData(scriptData) {
        const container = document.getElementById('scriptContainer');
        if (!container) return;

        if (scriptData.error) {
            container.innerHTML = `<div class="error">Script Analysis Error: ${this.escapeHtml(scriptData.error)}</div>`;
            return;
        }

        let html = `
            <div class="data-item">
                <div class="data-key">Suspicious</div>
                <div class="data-value ${scriptData.suspicious ? 'status-suspicious' : 'status-clean'}">
                    ${scriptData.suspicious ? 'YES' : 'NO'}
                </div>
            </div>
        `;

        if (scriptData.pattern_count !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">Patterns Found</div>
                    <div class="data-value">${scriptData.pattern_count}</div>
                </div>
            `;
        }

        if (scriptData.patterns_found && scriptData.patterns_found.length > 0) {
            html += `
                <div class="data-item">
                    <div class="data-key">Pattern Types</div>
                    <div class="data-value">${scriptData.patterns_found.join(', ')}</div>
                </div>
            `;
        }

        if (scriptData.analysis) {
            html += `
                <div class="data-item">
                    <div class="data-key">Analysis</div>
                    <div class="data-value">${this.escapeHtml(scriptData.analysis)}</div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    updateFileValidation(validationData) {
        const container = document.getElementById('validationContainer');
        if (!container) return;

        if (validationData.error) {
            container.innerHTML = `<div class="error">Validation Error: ${this.escapeHtml(validationData.error)}</div>`;
            return;
        }

        let html = '';

        if (validationData.file_extension !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">File Extension</div>
                    <div class="data-value">${validationData.file_extension}</div>
                </div>
            `;
        }

        if (validationData.detected_mime !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">Detected MIME</div>
                    <div class="data-value">${validationData.detected_mime}</div>
                </div>
            `;
        }

        if (validationData.is_valid !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">File Valid</div>
                    <div class="data-value ${validationData.is_valid ? 'status-valid' : 'status-invalid'}">
                        ${validationData.is_valid ? 'YES' : 'NO'}
                    </div>
                </div>
            `;
        }

        container.innerHTML = html || '<div class="no-data">No validation data available</div>';
    }

    updateHashData(hashData) {
        const container = document.getElementById('hashContainer');
        if (!container) return;

        if (hashData.error) {
            container.innerHTML = `<div class="error">Hash Error: ${this.escapeHtml(hashData.error)}</div>`;
            return;
        }

        let html = '';
        const hashFields = ['md5', 'sha1', 'sha256'];

        hashFields.forEach(hashType => {
            if (hashData[hashType]) {
                html += `
                    <div class="data-item">
                        <div class="data-key">${hashType.toUpperCase()}</div>
                        <div class="data-value hash">${hashData[hashType]}</div>
                    </div>
                `;
            }
        });

        if (hashData.file_size !== undefined) {
            html += `
                <div class="data-item">
                    <div class="data-key">File Size</div>
                    <div class="data-value">${this.formatFileSize(hashData.file_size)}</div>
                </div>
            `;
        }

        container.innerHTML = html || '<div class="no-data">No hash data available</div>';
    }

    async showCybersecurityInfo() {
        console.log('📚 Loading cybersecurity information...');

        try {
            this.showModal();

            const container = document.getElementById('conceptsContainer');
            if (container) {
                container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading cybersecurity information...</div>';
            }

            const response = await fetch('/api/info');
            if (!response.ok) {
                throw new Error(`Failed to load info: ${response.status}`);
            }

            const data = await response.json();
            this.displayCybersecurityInfo(data);

        } catch (error) {
            console.error('❌ Failed to load cybersecurity info:', error);
            const container = document.getElementById('conceptsContainer');
            if (container) {
                container.innerHTML = `<div class="error">Error: ${this.escapeHtml(error.message)}</div>`;
            }
        }
    }

    displayCybersecurityInfo(data) {
        const container = document.getElementById('conceptsContainer');
        if (!container) return;

        let html = '';

        // Display concepts
        const concepts = data.concepts || {};
        for (const [name, info] of Object.entries(concepts)) {
            html += `
                <div class="concept-item">
                    <h3>${name.replace(/_/g, ' ').toUpperCase()}</h3>
                    ${info.description ? `<p><strong>Description:</strong> ${this.escapeHtml(info.description)}</p>` : ''}
                    ${info.risks ? `<p><strong>Risks:</strong> ${this.escapeHtml(info.risks)}</p>` : ''}
                    ${info.mitigation ? `<p><strong>Mitigation:</strong> ${this.escapeHtml(info.mitigation)}</p>` : ''}
                    ${info.calculation ? `<p><strong>Calculation:</strong> ${this.escapeHtml(info.calculation)}</p>` : ''}
                    ${info.interpretation ? `<p><strong>Interpretation:</strong> ${this.escapeHtml(info.interpretation)}</p>` : ''}
                </div>
            `;
        }

        // Display tools used
        const tools = data.tools_used || {};
        if (Object.keys(tools).length > 0) {
            html += '<div class="concept-item"><h3>TOOLS &amp; TECHNOLOGIES</h3>';
            for (const [tool, description] of Object.entries(tools)) {
                html += `<p><strong>${this.escapeHtml(tool)}:</strong> ${this.escapeHtml(description)}</p>`;
            }
            html += '</div>';
        }

        container.innerHTML = html;
    }

    showModal() {
        if (this.modal) {
            this.modal.style.display = 'block';
        }
    }

    hideModal() {
        if (this.modal) {
            this.modal.style.display = 'none';
        }
    }

    showLoading(message = 'Processing...') {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = 'flex';
            const loadingText = document.getElementById('loadingText');
            if (loadingText) {
                loadingText.textContent = message;
            }
        }
    }

    hideLoading() {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = 'none';
        }
    }

    showAlert(message, type = 'info') {
        console.log(`📢 Alert (${type}): ${message}`);

        // Create alert container if it doesn't exist
        let alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) {
            alertContainer = document.createElement('div');
            alertContainer.id = 'alertContainer';
            alertContainer.className = 'alert-container';
            document.body.appendChild(alertContainer);
        }

        // Create alert element
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;

        // Icons for different alert types
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        alert.innerHTML = `
            <i class="${icons[type] || icons.info}"></i>
            <span>${this.escapeHtml(message)}</span>
            <span class="alert-close">&times;</span>
        `;

        // Add close functionality
        const closeBtn = alert.querySelector('.alert-close');
        closeBtn.addEventListener('click', () => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(400px)';
            setTimeout(() => alert.remove(), 300);
        });

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateX(400px)';
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);

        alertContainer.appendChild(alert);
    }

    async checkHealth() {
        console.log('🏥 Checking system health...');

        try {
            const response = await fetch('/health');
            if (response.ok) {
                const health = await response.json();
                console.log('✅ System health:', health);

                let message = `System Status: ${health.status || 'Unknown'}`;
                if (health.version) {
                    message += ` (v${health.version})`;
                }

                this.showAlert(message, 'success');
            } else {
                this.showAlert('System health check failed', 'warning');
            }
        } catch (error) {
            console.error('❌ Health check failed:', error);
            this.showAlert('Could not connect to server', 'error');
        }
    }
}

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.metaScanApp = new MetaScanApp();
});

// Also initialize if DOM is already loaded
if (document.readyState === 'loading') {
    // DOM still loading, wait for DOMContentLoaded event
} else {
    // DOM already loaded
    window.metaScanApp = new MetaScanApp();
}