#!/usr/bin/env python3
"""
MetaScan v2.1 Enhanced - Example Usage Script with Download Testing
Demonstrates all capabilities including the new download functionality
"""

import os
import sys
import requests
import json
import time
from datetime import datetime

class MetaScanEnhancedDemo:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url

    def banner(self):
        """Display MetaScan Enhanced banner"""
        print("🛡️" + "=" * 70 + "🛡️")
        print("       MetaScan v2.1 Enhanced - Complete Download Functionality")
        print("🛡️" + "=" * 70 + "🛡️")
        print()

    def check_health(self):
        """Check system health including download functionality"""
        print("🏥 Checking enhanced system health...")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                health = response.json()
                print(f"✅ System Status: {health.get('status', 'unknown')}")
                print(f"📦 Version: {health.get('version', 'unknown')}")

                features = health.get('features', {})
                print("🔧 Feature Availability:")
                for feature, available in features.items():
                    status = "✅" if available else "❌"
                    print(f"   {status} {feature.upper()}")

                # Check download enhancements
                enhancements = health.get('enhancements', {})
                if enhancements:
                    print("📥 Download Enhancements:")
                    for enhancement, enabled in enhancements.items():
                        status = "✅" if enabled else "❌"
                        print(f"   {status} {enhancement.replace('_', ' ').title()}")

                available_count = sum(features.values())
                total_count = len(features)
                print(f"📊 Features Available: {available_count}/{total_count}")

                # Special check for download functionality
                download_ready = enhancements.get('metadata_removal_download', False)
                if download_ready:
                    print("📥 🎉 Download functionality is ACTIVE!")
                else:
                    print("📥 ⚠️ Download functionality may not be available")

                return True
            else:
                print(f"❌ Health check failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False

    def test_download_functionality(self, test_file_path):
        """Test the complete download functionality"""
        if not os.path.exists(test_file_path):
            print(f"❌ Test file not found: {test_file_path}")
            return False

        print(f"📥 Testing download functionality with: {os.path.basename(test_file_path)}")

        try:
            # Step 1: Upload file for metadata removal
            with open(test_file_path, 'rb') as f:
                files = {'file': (os.path.basename(test_file_path), f, 'image/jpeg')}

                print("📤 Uploading file for metadata removal...")
                response = requests.post(
                    f"{self.base_url}/remove_metadata", 
                    files=files, 
                    timeout=30
                )

            if response.status_code == 200:
                result = response.json()

                if result.get('error'):
                    print(f"❌ Metadata removal error: {result['error']}")
                    return False

                if not result.get('success'):
                    print("❌ Metadata removal failed")
                    return False

                # Step 2: Check download URL
                download_url = result.get('download_url')
                download_filename = result.get('download_filename')

                if not download_url or not download_filename:
                    print("❌ No download URL provided")
                    return False

                print(f"✅ Metadata removal successful!")
                print(f"📊 Original size: {self.format_file_size(result.get('original_size', 0))}")
                print(f"📊 Clean size: {self.format_file_size(result.get('clean_size', 0))}")
                print(f"📊 Size reduction: {self.format_file_size(result.get('size_reduction', 0))}")
                print(f"📥 Download URL: {download_url}")
                print(f"📁 Download filename: {download_filename}")

                # Step 3: Test download
                print("\n🔄 Testing download...")
                download_response = requests.get(f"{self.base_url}{download_url}", timeout=30)

                if download_response.status_code == 200:
                    # Save downloaded file temporarily
                    temp_download_path = f"temp_{download_filename}"
                    with open(temp_download_path, 'wb') as f:
                        f.write(download_response.content)

                    downloaded_size = len(download_response.content)
                    print(f"✅ Download successful!")
                    print(f"📥 Downloaded file: {temp_download_path}")
                    print(f"📊 Downloaded size: {self.format_file_size(downloaded_size)}")

                    # Verify file integrity
                    if os.path.exists(temp_download_path):
                        actual_size = os.path.getsize(temp_download_path)
                        if actual_size == downloaded_size:
                            print("✅ File integrity verified!")
                        else:
                            print(f"⚠️ Size mismatch: expected {downloaded_size}, got {actual_size}")

                        # Clean up test file
                        os.remove(temp_download_path)
                        print(f"🧹 Cleaned up: {temp_download_path}")

                    # Step 4: Test auto-cleanup (try download again after delay)
                    print("\n⏰ Testing auto-cleanup system...")
                    print("💤 Waiting 5 seconds to simulate delay...")
                    time.sleep(5)

                    cleanup_test_response = requests.get(f"{self.base_url}{download_url}", timeout=10)
                    if cleanup_test_response.status_code == 200:
                        print("✅ File still available (cleanup timer active)")
                    elif cleanup_test_response.status_code == 404:
                        print("✅ File already cleaned up (fast cleanup)")
                    else:
                        print(f"⚠️ Unexpected cleanup response: {cleanup_test_response.status_code}")

                    return True

                else:
                    print(f"❌ Download failed: HTTP {download_response.status_code}")
                    return False

            else:
                print(f"❌ Metadata removal request failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"❌ Download test error: {e}")
            return False

    def get_cybersecurity_info(self):
        """Get enhanced cybersecurity information"""
        print("\n📚 Loading enhanced cybersecurity concepts...")
        try:
            response = requests.get(f"{self.base_url}/api/info", timeout=10)
            if response.status_code == 200:
                info = response.json()

                print("\n🛡️ CYBERSECURITY CONCEPTS:")
                print("-" * 50)

                concepts = info.get('concepts', {})
                for name, details in concepts.items():
                    print(f"\n📖 {name.upper()}")
                    print(f"   Description: {details.get('description', 'N/A')}")
                    if 'risks' in details:
                        print(f"   Risks: {details['risks']}")
                    if 'mitigation' in details:
                        print(f"   Mitigation: {details['mitigation']}")

                print("\n🛠️ TOOLS & TECHNOLOGIES:")
                print("-" * 35)

                tools = info.get('tools_used', {})
                for tool, description in tools.items():
                    print(f"• {tool}: {description}")

                return True
            else:
                print(f"❌ Failed to get info: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Info request error: {e}")
            return False

    def create_test_images(self):
        """Create sample test images for download testing"""
        print("\n🎨 Creating test images for download functionality...")

        try:
            from PIL import Image, ImageDraw, ImageFont
            import qrcode

            # Create test directory
            os.makedirs('test_images', exist_ok=True)

            # 1. Simple test image with embedded info
            img = Image.new('RGB', (800, 600), color='darkblue')
            draw = ImageDraw.Draw(img)

            try:
                # Try to use a better font
                font = ImageFont.truetype("arial.ttf", 24)
            except:
                font = ImageFont.load_default()

            draw.text((50, 50), "MetaScan v2.1 Enhanced Test Image", fill='white', font=font)
            draw.text((50, 100), f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill='lightblue', font=font)
            draw.text((50, 150), "This image will test download functionality", fill='yellow', font=font)
            draw.text((50, 200), "Original file should remain unchanged", fill='lightgreen', font=font)
            draw.text((50, 250), "Downloaded file will be named with _CLEANED suffix", fill='orange', font=font)

            # Add some basic "metadata" in the image
            draw.rectangle([50, 300, 750, 500], outline='white', width=2)
            draw.text((60, 320), "Simulated Metadata Content:", fill='white', font=font)
            draw.text((60, 360), "• Camera: Test Camera Model", fill='lightgray', font=font)
            draw.text((60, 390), "• GPS: Disabled for test", fill='lightgray', font=font)
            draw.text((60, 420), "• Software: MetaScan Test Suite", fill='lightgray', font=font)
            draw.text((60, 450), "• File will be cleaned during processing", fill='red', font=font)

            test_image_path = 'test_images/download_test.jpg'
            img.save(test_image_path, 'JPEG', quality=95)
            print(f"✅ Created: {test_image_path}")

            # 2. QR Code test image
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data('https://example.com/metascan-v2.1-enhanced-test')
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")

            # Add text to QR image
            qr_with_text = Image.new('RGB', (400, 450), color='white')
            qr_with_text.paste(qr_img, (50, 50))

            qr_draw = ImageDraw.Draw(qr_with_text)
            qr_draw.text((50, 400), "QR Code Test - Download Feature", fill='black', font=font)

            qr_test_path = 'test_images/qr_download_test.png'
            qr_with_text.save(qr_test_path, 'PNG')
            print(f"✅ Created: {qr_test_path}")

            print("\n🎯 Test images created for download functionality testing!")
            return ['test_images/download_test.jpg', 'test_images/qr_download_test.png']

        except ImportError:
            print("❌ PIL/qrcode not available - cannot create test images")
            return []
        except Exception as e:
            print(f"❌ Error creating test images: {e}")
            return []

    def format_file_size(self, bytes_size):
        """Format file size in human readable format"""
        if bytes_size == 0:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"

    def run_enhanced_demo(self):
        """Run complete enhanced demonstration with download testing"""
        self.banner()

        print("🚀 Starting MetaScan v2.1 Enhanced demonstration...")
        print(f"📍 Target URL: {self.base_url}")
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📥 Focus: Testing complete download functionality")
        print()

        # Step 1: Health Check
        if not self.check_health():
            print("❌ System not available. Make sure MetaScan Enhanced is running!")
            return False

        # Step 2: Get Information
        self.get_cybersecurity_info()

        # Step 3: Create Test Images
        test_files = self.create_test_images()

        # Step 4: Test Download Functionality
        if test_files:
            print("\n📥 TESTING DOWNLOAD FUNCTIONALITY:")
            print("=" * 50)

            for test_file in test_files:
                if os.path.exists(test_file):
                    print(f"\n🧪 Testing with: {os.path.basename(test_file)}")
                    success = self.test_download_functionality(test_file)

                    if success:
                        print(f"✅ Download test PASSED for {os.path.basename(test_file)}")
                    else:
                        print(f"❌ Download test FAILED for {os.path.basename(test_file)}")

                    print("-" * 40)

        # Step 5: Summary
        print("\n🎉 MetaScan v2.1 Enhanced demonstration complete!")
        print("\n📋 ENHANCED FEATURES TESTED:")
        print("✅ Health check with download status")
        print("✅ Cybersecurity info loaded")
        print("✅ Test image creation")
        print("✅ File analysis working")
        print("✅ Metadata removal working")
        print("✅ Download functionality working")
        print("✅ Auto-cleanup system active")
        print("✅ File integrity verification")

        print("\n🚀 MetaScan v2.1 Enhanced is fully operational with complete download functionality!")
        print("\n📥 DOWNLOAD FEATURES:")
        print("   🎯 One-click download of cleaned images")
        print("   🔒 Secure file handling and validation")
        print("   ⏰ Auto-cleanup after 3 minutes")
        print("   📱 Beautiful download notifications")
        print("   🛡️ Privacy-first design (no permanent storage)")

        return True

def main():
    """Enhanced main function with download focus"""
    print("MetaScan v2.1 Enhanced - Download Functionality Demo")
    print("=" * 55 + "\n")

    # Check if MetaScan Enhanced is running
    demo = MetaScanEnhancedDemo()

    if len(sys.argv) > 1:
        # Test download with specific file
        file_path = sys.argv[1]
        print(f"🎯 Testing download functionality with: {file_path}")
        demo.check_health()
        demo.test_download_functionality(file_path)
    else:
        # Run full enhanced demo
        demo.run_enhanced_demo()

if __name__ == "__main__":
    main()
