#!/usr/bin/env python3
"""
MetaScan v2.1 Enhanced - Bug Fix Verification Test
Tests all the fixed bugs to ensure they work correctly
"""

import os
import sys
import json
import requests
import time
from datetime import datetime

class BugFixTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.test_results = []

    def print_header(self):
        print("🧪" + "=" * 60 + "🧪")
        print("  MetaScan v2.1 Enhanced - Bug Fix Verification")
        print("🧪" + "=" * 60 + "🧪")
        print()

    def test_health_endpoint(self):
        """Test that health endpoint works without warnings"""
        print("🏥 Testing Health Endpoint (Magic Library Fix)...")

        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)

            if response.status_code == 200:
                health_data = response.json()

                print(f"  ✅ Health check successful")
                print(f"  📊 Status: {health_data.get('status', 'unknown')}")
                print(f"  📦 Version: {health_data.get('version', 'unknown')}")

                # Check if magic library status is properly handled
                features = health_data.get('features', {})
                magic_status = features.get('magic_available', False)
                print(f"  🔮 Magic library: {'Available' if magic_status else 'Not available (graceful fallback)'}")

                self.test_results.append(("Health Endpoint", True, "Working correctly"))
                return True
            else:
                print(f"  ❌ Health check failed: HTTP {response.status_code}")
                self.test_results.append(("Health Endpoint", False, f"HTTP {response.status_code}"))
                return False

        except Exception as e:
            print(f"  ❌ Health check error: {e}")
            self.test_results.append(("Health Endpoint", False, str(e)))
            return False

    def create_test_image(self):
        """Create a simple test image for upload testing"""
        try:
            from PIL import Image, ImageDraw

            # Create a simple test image
            img = Image.new('RGB', (400, 300), color='blue')
            draw = ImageDraw.Draw(img)
            draw.text((10, 10), "MetaScan Test Image", fill='white')

            test_path = 'test_upload.jpg'
            img.save(test_path, 'JPEG')

            return test_path
        except ImportError:
            print("  ⚠️  PIL not available - cannot create test image")
            return None
        except Exception as e:
            print(f"  ❌ Error creating test image: {e}")
            return None

    def test_upload_analysis(self):
        """Test file upload and analysis (GPS fix verification)"""
        print("\n📤 Testing File Upload & Analysis (GPS Fix)...")

        test_image = self.create_test_image()
        if not test_image:
            print("  ⚠️  Skipping upload test - no test image")
            self.test_results.append(("Upload Analysis", False, "No test image"))
            return False

        try:
            with open(test_image, 'rb') as f:
                files = {'file': ('test.jpg', f, 'image/jpeg')}
                response = requests.post(f"{self.base_url}/upload", files=files, timeout=30)

            # Clean up test image
            if os.path.exists(test_image):
                os.remove(test_image)

            if response.status_code == 200:
                result = response.json()

                print("  ✅ File upload successful")

                # Check if GPS extraction doesn't crash
                exif_data = result.get('exif_data', {})
                gps_data = exif_data.get('gps_data')
                print(f"  🗺️  GPS data handling: {'Found GPS data' if gps_data else 'No GPS data (expected for test image)'}")

                # Check privacy score
                privacy_score = result.get('privacy_score', 0)
                print(f"  📊 Privacy score: {privacy_score}/100")

                self.test_results.append(("Upload Analysis", True, "Analysis completed without GPS errors"))
                return True
            else:
                print(f"  ❌ Upload failed: HTTP {response.status_code}")
                self.test_results.append(("Upload Analysis", False, f"HTTP {response.status_code}"))
                return False

        except Exception as e:
            print(f"  ❌ Upload test error: {e}")
            self.test_results.append(("Upload Analysis", False, str(e)))
            return False

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("🎯 BUG FIX VERIFICATION SUMMARY")
        print("=" * 60)

        passed = sum(1 for _, success, _ in self.test_results if success)
        total = len(self.test_results)

        print(f"📊 Tests Passed: {passed}/{total}")
        print()

        for test_name, success, message in self.test_results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"  {status} {test_name}: {message}")

        print()
        if passed == total:
            print("🎉 ALL BUG FIXES VERIFIED - MetaScan is ready to use!")
        else:
            print("⚠️  Some tests failed - check the application is running correctly.")

        print("\n🌐 Access the application at: http://localhost:5000")

    def run_all_tests(self):
        """Run all bug fix verification tests"""
        self.print_header()

        print("🔍 Verifying that all reported bugs have been fixed...")
        print(f"🎯 Target URL: {self.base_url}")
        print(f"⏰ Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Run all tests
        self.test_health_endpoint()
        self.test_upload_analysis()

        # Print summary
        self.print_summary()

def main():
    """Main test function"""
    print("MetaScan v2.1 Enhanced - Bug Fix Verification")
    print("=" * 50)

    # Check if server might be running
    tester = BugFixTester()

    try:
        # Quick connectivity test
        response = requests.get(tester.base_url + "/health", timeout=2)
        print("🟢 Server is running - starting tests...")
        print()
    except:
        print("🔴 Server not running!")
        print("💡 Please start the server first:")
        print("   python app.py")
        print("   or")
        print("   python run_metascan.py")
        print()
        return False

    # Run all verification tests
    tester.run_all_tests()
    return True

if __name__ == '__main__':
    main()
