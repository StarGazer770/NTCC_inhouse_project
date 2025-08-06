#!/usr/bin/env python3
"""
MetaScan v2.1 Enhanced - Quick Setup and Run Script
Automatically installs dependencies and runs the application
"""

import os
import sys
import subprocess
import time

def print_banner():
    print("🛡️" + "=" * 60 + "🛡️")
    print("  MetaScan v2.1 Enhanced - Bug-Free Setup Script")
    print("🛡️" + "=" * 60 + "🛡️")
    print()

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing core dependencies...")

    # Core dependencies that are required
    core_deps = [
        'Flask==3.0.3',
        'Werkzeug==3.0.3', 
        'Pillow==10.4.0'
    ]

    # Optional dependencies (install if possible)
    optional_deps = [
        'opencv-python-headless==4.10.0.84',
        'numpy==1.26.4',
        'geopy==2.4.1'
    ]

    print("🔧 Installing core dependencies (required)...")
    for dep in core_deps:
        try:
            print(f"  Installing {dep}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
            print(f"  ✅ {dep} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to install {dep}: {e}")
            return False

    print("\n🌟 Installing optional dependencies (enhanced features)...")
    for dep in optional_deps:
        try:
            print(f"  Installing {dep}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
            print(f"  ✅ {dep} installed successfully")
        except subprocess.CalledProcessError:
            print(f"  ⚠️  {dep} installation failed (optional - app will work without it)")

    return True

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    try:
        os.makedirs('uploads', exist_ok=True)
        print("  ✅ All directories created")
        return True
    except Exception as e:
        print(f"  ❌ Error creating directories: {e}")
        return False

def run_application():
    """Run the MetaScan application"""
    print("\n🚀 Starting MetaScan v2.1 Enhanced...")
    print("🌐 The application will be available at: http://localhost:5000")
    print("⏹️  Press Ctrl+C to stop the application")
    print()

    try:
        # Run the application
        subprocess.run([sys.executable, 'app.py'])
    except KeyboardInterrupt:
        print("\n\n👋 MetaScan application stopped by user")
    except FileNotFoundError:
        print("❌ app.py not found!")
        return False
    except Exception as e:
        print(f"❌ Error running application: {e}")
        return False

    return True

def main():
    """Main setup and run function"""
    print_banner()

    print("🔍 System Information:")
    print(f"   Python version: {sys.version}")
    print(f"   Platform: {sys.platform}")
    print(f"   Current directory: {os.getcwd()}")
    print()

    # Step 1: Install dependencies
    if not install_dependencies():
        print("❌ Dependency installation failed!")
        return False

    # Step 2: Create directories
    if not create_directories():
        print("❌ Directory creation failed!")
        return False

    # Step 3: Run application
    print("\n" + "="*50)
    run_application()

    print("\n🎉 Setup and execution completed!")
    return True

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Setup interrupted by user")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
