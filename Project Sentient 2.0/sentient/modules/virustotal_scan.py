import requests
import hashlib
import time
import base64
import os

# ANSI color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}
    
    def scan_url(self, url):
        """Scan a URL with VirusTotal"""
        try:
            # Submit URL for scanning
            submit_url = f"{self.base_url}/urls"
            data = {"url": url}
            
            response = requests.post(submit_url, headers=self.headers, data=data)
            if response.status_code != 200:
                return {"error": f"Failed to submit URL: {response.status_code}"}
            
            # Get the analysis ID
            result = response.json()
            analysis_id = result["data"]["id"]
            
            # Wait and get results
            time.sleep(2)  # Give VirusTotal time to process
            
            analysis_url = f"{self.base_url}/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=self.headers)
            
            if analysis_response.status_code == 200:
                return self._format_url_results(analysis_response.json())
            else:
                # Try getting existing report by URL ID
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report_url = f"{self.base_url}/urls/{url_id}"
                report_response = requests.get(report_url, headers=self.headers)
                
                if report_response.status_code == 200:
                    return self._format_url_results(report_response.json())
                else:
                    return {"error": "Could not retrieve analysis results"}
                    
        except Exception as e:
            return {"error": str(e)}
    
    def scan_file_hash(self, file_hash):
        """Scan a file hash with VirusTotal"""
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return self._format_file_results(response.json())
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal database"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def scan_file(self, file_path):
        """Scan a local file with VirusTotal"""
        try:
            if not os.path.exists(file_path):
                return {"error": "File does not exist"}
            
            # Calculate file hash first to check if it's already scanned
            file_hash = self._calculate_file_hash(file_path)
            
            # Try to get existing report first
            existing_report = self.scan_file_hash(file_hash)
            if "error" not in existing_report:
                existing_report["note"] = "Results from existing database scan"
                return existing_report
            
            # If file size is too large (>650MB), only return hash scan
            file_size = os.path.getsize(file_path)
            if file_size > 650 * 1024 * 1024:  # 650MB limit
                return {
                    "error": "File too large for upload",
                    "hash": file_hash,
                    "size": file_size,
                    "suggestion": f"Use hash scan: scan hash {file_hash}"
                }
            
            # Upload file for scanning
            upload_url = f"{self.base_url}/files"
            
            with open(file_path, 'rb') as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(upload_url, headers=self.headers, files=files)
            
            if response.status_code != 200:
                return {"error": f"Failed to upload file: {response.status_code}"}
            
            # Get analysis ID and wait for results
            result = response.json()
            analysis_id = result["data"]["id"]
            
            # Wait for analysis to complete
            time.sleep(5)  # File analysis takes longer
            
            analysis_url = f"{self.base_url}/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=self.headers)
            
            if analysis_response.status_code == 200:
                return self._format_file_results(analysis_response.json())
            else:
                return {"error": "Analysis not ready, try again later"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    def _format_url_results(self, data):
        """Format URL scan results"""
        try:
            # Check if we have the expected data structure
            if "data" not in data or "attributes" not in data["data"]:
                return {"error": "Invalid response format from VirusTotal"}
            
            attributes = data["data"]["attributes"]
            
            # Handle different response formats
            if "stats" in attributes:
                # Full analysis results
                stats = attributes["stats"]
                result = {
                    "url": attributes.get("url", "Unknown"),
                    "scan_date": attributes.get("date", "Unknown"),
                    "total_engines": stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0) + stats.get("undetected", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "detections": []
                }
                
                # Add specific detections if available
                if "results" in attributes:
                    engines = attributes["results"]
                    for engine, details in engines.items():
                        if details.get("category") in ["malicious", "suspicious"]:
                            result["detections"].append({
                                "engine": engine,
                                "category": details.get("category", "Unknown"),
                                "result": details.get("result", "Unknown")
                            })
                
                return result
            else:
                # Pending analysis or basic info
                return {
                    "url": attributes.get("url", "Unknown"),
                    "status": "Analysis pending or incomplete",
                    "message": "Try again in a few moments"
                }
            
        except Exception as e:
            return {"error": f"Failed to parse URL results: {str(e)}"}
    
    def _format_file_results(self, data):
        """Format file scan results"""
        try:
            # Check if we have the expected data structure
            if "data" not in data or "attributes" not in data["data"]:
                return {"error": "Invalid response format from VirusTotal"}
            
            attributes = data["data"]["attributes"]
            
            # Handle different response formats
            if "last_analysis_stats" in attributes:
                stats = attributes["last_analysis_stats"]
                result = {
                    "file_name": attributes.get("meaningful_name", attributes.get("names", ["Unknown"])[0] if attributes.get("names") else "Unknown"),
                    "file_size": attributes.get("size", 0),
                    "file_type": attributes.get("type_description", "Unknown"),
                    "sha256": attributes.get("sha256", "Unknown"),
                    "md5": attributes.get("md5", "Unknown"),
                    "scan_date": attributes.get("last_analysis_date", "Unknown"),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "detections": []
                }
                
                # Add specific detections if available
                if "last_analysis_results" in attributes:
                    engines = attributes["last_analysis_results"]
                    for engine, details in engines.items():
                        if details.get("category") in ["malicious", "suspicious"]:
                            result["detections"].append({
                                "engine": engine,
                                "category": details.get("category", "Unknown"),
                                "result": details.get("result", "Unknown")
                            })
                
                return result
            else:
                # Basic file info without scan results
                return {
                    "file_name": attributes.get("meaningful_name", "Unknown"),
                    "sha256": attributes.get("sha256", "Unknown"),
                    "md5": attributes.get("md5", "Unknown"),
                    "status": "File found but no analysis available",
                    "message": "File may not have been scanned yet"
                }
            
        except Exception as e:
            return {"error": f"Failed to parse file results: {str(e)}"}

# Default API key - you can change this
DEFAULT_API_KEY = "5fd4e0207c8f22835a09f45b966b29edc4140569f33c4ac305272a58a93dc6ba"

# Initialize scanner with default API key
vt_scanner = VirusTotalScanner(DEFAULT_API_KEY)

def virustotal_scan_url(url, api_key=None):
    """Scan URL with VirusTotal"""
    if api_key:
        scanner = VirusTotalScanner(api_key)
    else:
        scanner = vt_scanner
    
    return scanner.scan_url(url)

def virustotal_scan_file(file_path, api_key=None):
    """Scan file with VirusTotal"""
    if api_key:
        scanner = VirusTotalScanner(api_key)
    else:
        scanner = vt_scanner
    
    return scanner.scan_file(file_path)

def virustotal_scan_hash(file_hash, api_key=None):
    """Scan file hash with VirusTotal"""
    if api_key:
        scanner = VirusTotalScanner(api_key)
    else:
        scanner = vt_scanner
    
    return scanner.scan_file_hash(file_hash)

def display_scan_results(results):
    """Display formatted scan results"""
    if "error" in results:
        print(f"{RED}[ERROR]{RESET} {results['error']}")
        return
    
    # Handle pending/incomplete analysis
    if "status" in results:
        print(f"{YELLOW}[STATUS]{RESET} {results['status']}")
        if "message" in results:
            print(f"Message: {results['message']}")
        if "url" in results:
            print(f"URL: {results['url']}")
        return
    
    if "url" in results:
        # URL scan results
        print(f"{CYAN}[URL SCAN RESULTS]{RESET}")
        print(f"URL: {results['url']}")
        if results.get('scan_date') != "Unknown":
            try:
                scan_date = int(results['scan_date'])
                print(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_date))}")
            except:
                print(f"Scan Date: {results['scan_date']}")
        
        print(f"Total Engines: {results.get('total_engines', 0)}")
        
        malicious = results.get('malicious', 0)
        suspicious = results.get('suspicious', 0)
        
        if malicious > 0:
            print(f"{RED}Malicious: {malicious}{RESET}")
        else:
            print(f"{GREEN}Malicious: {malicious}{RESET}")
            
        if suspicious > 0:
            print(f"{YELLOW}Suspicious: {suspicious}{RESET}")
        else:
            print(f"Suspicious: {suspicious}")
            
        print(f"Harmless: {results.get('harmless', 0)}")
        print(f"Undetected: {results.get('undetected', 0)}")
        
    else:
        # File scan results
        print(f"{CYAN}[FILE SCAN RESULTS]{RESET}")
        print(f"File: {results.get('file_name', 'Unknown')}")
        print(f"Size: {results.get('file_size', 0)} bytes")
        print(f"Type: {results.get('file_type', 'Unknown')}")
        print(f"SHA256: {results.get('sha256', 'Unknown')}")
        print(f"MD5: {results.get('md5', 'Unknown')}")
        
        if results.get('scan_date') != "Unknown":
            try:
                scan_date = int(results['scan_date'])
                print(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_date))}")
            except:
                print(f"Scan Date: {results['scan_date']}")
        
        print(f"Total Engines: {results.get('total_engines', 0)}")
        
        malicious = results.get('malicious', 0)
        suspicious = results.get('suspicious', 0)
        
        if malicious > 0:
            print(f"{RED}Malicious: {malicious}{RESET}")
        else:
            print(f"{GREEN}Malicious: {malicious}{RESET}")
            
        if suspicious > 0:
            print(f"{YELLOW}Suspicious: {suspicious}{RESET}")
        else:
            print(f"Suspicious: {suspicious}")
            
        print(f"Harmless: {results.get('harmless', 0)}")
        print(f"Undetected: {results.get('undetected', 0)}")
    
    # Show detections if any
    if results.get('detections'):
        print(f"\n{RED}[DETECTIONS]{RESET}")
        for detection in results['detections']:
            print(f"  {detection['engine']}: {detection['result']} ({detection['category']})")
    else:
        print(f"\n{GREEN}[CLEAN] No threats detected{RESET}")

# CLI functions for integration with main Sentient AI
def virustotal_url_cli(url):
    """CLI wrapper for URL scanning"""
    results = virustotal_scan_url(url)
    display_scan_results(results)
    return results

def virustotal_file_cli(file_path):
    """CLI wrapper for file scanning"""
    results = virustotal_scan_file(file_path)
    display_scan_results(results)
    return results

def virustotal_hash_cli(file_hash):
    """CLI wrapper for hash scanning"""
    results = virustotal_scan_hash(file_hash)
    display_scan_results(results)
    return results

if __name__ == "__main__":
    # Test the module
    print("VirusTotal Scanner Test")
    print("1. Scanning a URL...")
    virustotal_url_cli("http://malware.wicar.org/data/eicar.com")
    
    print("\n2. Scanning a hash...")
    # EICAR test file hash
    virustotal_hash_cli("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")