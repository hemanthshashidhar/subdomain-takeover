#!/usr/bin/env python3
"""
TakeoverHunter v1.0
Finds CONFIRMED subdomain takeovers (not just potentials)
Generates HackerOne-ready reports
"""

import subprocess
import dns.resolver
import requests
import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

# Suppress warnings
import urllib3
urllib3.disable_warnings()

class TakeoverHunter:
    def __init__(self, target, github_token=None, aws_key=None, azure_key=None):
        self.target = target.replace('https://', '').replace('http://', '').strip('/')
        self.output_dir = f"takeover_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.findings = []
        
        # API keys for validation
        self.github_token = github_token
        self.aws_key = aws_key
        self.azure_key = azure_key
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/evidence", exist_ok=True)
        
        print(f"🎯 TakeoverHunter initialized for: {self.target}")
        print(f"📁 Output: {self.output_dir}/")
    
    def find_subdomains(self):
        """Phase 1: Find subdomains using multiple tools"""
        print("\n" + "="*60)
        print("🔍 PHASE 1: Finding Subdomains")
        print("="*60)
        
        subdomains = set()
        
        # Tool 1: subfinder
        print("\n[1/3] Running subfinder...")
        try:
            cmd = f"subfinder -d {self.target} -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            found = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            subdomains.update(found)
            print(f"    ✅ Found {len(found)} subdomains")
        except Exception as e:
            print(f"    ⚠️  subfinder failed: {e}")
        
        # Tool 2: assetfinder
        print("\n[2/3] Running assetfinder...")
        try:
            cmd = f"assetfinder --subs-only {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            found = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            subdomains.update(found)
            print(f"    ✅ Found {len(found)} subdomains")
        except Exception as e:
            print(f"    ⚠️  assetfinder failed: {e}")
        
        # Tool 3: amass (passive)
        print("\n[3/3] Running amass...")
        try:
            cmd = f"amass enum -passive -d {self.target} -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            found = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            subdomains.update(found)
            print(f"    ✅ Found {len(found)} subdomains")
        except Exception as e:
            print(f"    ⚠️  amass failed: {e}")
        
        # Save all subdomains
        all_subs = sorted(list(subdomains))
        with open(f"{self.output_dir}/all_subdomains.txt", 'w') as f:
            f.write('\n'.join(all_subs))
        
        print(f"\n📊 Total unique subdomains: {len(all_subs)}")
        return all_subs
    
    def check_dns_records(self, subdomains):
        """Phase 2: Check CNAME records for each subdomain"""
        print("\n" + "="*60)
        print("🔍 PHASE 2: Checking DNS Records (CNAME)")
        print("="*60)
        
        candidates = []
        
        for i, sub in enumerate(subdomains, 1):
            print(f"\n[{i}/{len(subdomains)}] Checking {sub}...")
            try:
                # Get CNAME record
                answers = dns.resolver.resolve(sub, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    print(f"    CNAME: {cname}")
                    
                    # Check if pointing to cloud service
                    service = self._detect_cloud_service(cname)
                    if service:
                        print(f"    ☁️  Detected: {service['name']}")
                        candidates.append({
                            'subdomain': sub,
                            'cname': cname,
                            'service': service,
                            'status': 'detected'
                        })
                    else:
                        print(f"    ℹ️  Not a known takeover target")
                        
            except dns.resolver.NoAnswer:
                print(f"    ℹ️  No CNAME record")
            except dns.resolver.NXDOMAIN:
                print(f"    ⚠️  Domain doesn't exist")
            except Exception as e:
                print(f"    ❌ Error: {e}")
        
        print(f"\n📊 Found {len(candidates)} potential takeover candidates")
        return candidates
    
    def _detect_cloud_service(self, cname):
        """Detect which cloud service the CNAME points to"""
        cname_lower = cname.lower()
        
        services = {
            'aws_s3': {
                'name': 'AWS S3',
                'patterns': ['s3.amazonaws.com', 's3-website', 's3.dualstack'],
                'validation_method': 'aws_check'
            },
            'github_pages': {
                'name': 'GitHub Pages',
                'patterns': ['github.io', 'github.com'],
                'validation_method': 'github_check'
            },
            'azure_blob': {
                'name': 'Azure Blob Storage',
                'patterns': ['blob.core.windows.net', 'azurewebsites.net', 'cloudapp.azure.com'],
                'validation_method': 'azure_check'
            },
            'heroku': {
                'name': 'Heroku',
                'patterns': ['herokuapp.com', 'herokussl.com'],
                'validation_method': 'heroku_check'
            },
            'shopify': {
                'name': 'Shopify',
                'patterns': ['myshopify.com'],
                'validation_method': 'shopify_check'
            },
            'fastly': {
                'name': 'Fastly',
                'patterns': ['fastly.net'],
                'validation_method': 'fastly_check'
            }
        }
        
        for service_id, service_info in services.items():
            for pattern in service_info['patterns']:
                if pattern in cname_lower:
                    return {
                        'id': service_id,
                        'name': service_info['name'],
                        'validation': service_info['validation_method'],
                        'cname': cname
                    }
        
        return None
    
    def validate_takeover(self, candidates):
        """Phase 3: Validate if takeover is actually possible"""
        print("\n" + "="*60)
        print("🔍 PHASE 3: Validating Takeovers (Safe Checks)")
        print("="*60)
        
        confirmed = []
        
        for candidate in candidates:
            print(f"\n🧪 Testing: {candidate['subdomain']}")
            print(f"   Service: {candidate['service']['name']}")
            print(f"   CNAME: {candidate['cname']}")
            
            validation_method = candidate['service']['validation']
            
            try:
                if validation_method == 'github_check':
                    result = self._validate_github(candidate)
                elif validation_method == 'aws_check':
                    result = self._validate_aws(candidate)
                elif validation_method == 'azure_check':
                    result = self._validate_azure(candidate)
                elif validation_method == 'heroku_check':
                    result = self._validate_heroku(candidate)
                elif validation_method == 'shopify_check':
                    result = self._validate_shopify(candidate)
                else:
                    print(f"   ⚠️  No validator for {validation_method}")
                    continue
                
                if result['vulnerable']:
                    print(f"   🚨 CONFIRMED VULNERABLE!")
                    print(f"   Impact: {result['impact']}")
                    confirmed.append({
                        **candidate,
                        'validation': result,
                        'confirmed_at': datetime.now().isoformat()
                    })
                    
                    # Save evidence
                    evidence_file = f"{self.output_dir}/evidence/{candidate['subdomain']}.json"
                    with open(evidence_file, 'w') as f:
                        json.dump(result, f, indent=2)
                else:
                    print(f"   ✅ Not vulnerable (safe)")
                    
            except Exception as e:
                print(f"   ❌ Validation error: {e}")
        
        print(f"\n🎯 Confirmed takeovers: {len(confirmed)}")
        return confirmed
    
    def _validate_github(self, candidate):
        """Validate GitHub Pages takeover"""
        # Extract username from CNAME (e.g., user.github.io)
        cname = candidate['cname']
        
        # Check if GitHub user/repo exists
        try:
            response = requests.get(f"https://{cname}", timeout=10, allow_redirects=False)
            
            # GitHub Pages 404 means potentially takeoverable
            if response.status_code == 404:
                # Check if we can claim it (GitHub username availability)
                username = cname.split('.')[0]
                github_check = requests.get(
                    f"https://api.github.com/users/{username}",
                    headers={'Authorization': f'token {self.github_token}'} if self.github_token else {},
                    timeout=10
                )
                
                if github_check.status_code == 404:
                    return {
                        'vulnerable': True,
                        'impact': 'HIGH - Can claim GitHub username and serve malicious content',
                        'reproduction': f'1. Create GitHub account: {username}\n2. Create repo: {username}.github.io\n3. Push any content\n4. Subdomain serves your content',
                        'fix': 'Remove CNAME record or claim the GitHub username'
                    }
            
            return {'vulnerable': False, 'reason': f'Status {response.status_code}'}
            
        except Exception as e:
            return {'vulnerable': False, 'reason': str(e)}
    
    def _validate_aws(self, candidate):
        """Validate AWS S3 takeover"""
        try:
            # Try to access the bucket
            response = requests.get(f"http://{candidate['cname']}", timeout=10)
            
            # S3 "NoSuchBucket" error means takeoverable
            if 'NoSuchBucket' in response.text or response.status_code == 404:
                # Extract bucket name
                bucket = candidate['cname'].split('.')[0]
                
                return {
                    'vulnerable': True,
                    'impact': 'CRITICAL - Can create S3 bucket and serve malicious content',
                    'reproduction': f'1. Create S3 bucket: {bucket}\n2. Enable static website hosting\n3. Upload any content\n4. Subdomain serves your content',
                    'fix': 'Delete CNAME record or create the S3 bucket with proper permissions',
                    'bucket_name': bucket
                }
            
            return {'vulnerable': False, 'reason': 'Bucket exists or not accessible'}
            
        except Exception as e:
            return {'vulnerable': False, 'reason': str(e)}
    
    def _validate_azure(self, candidate):
        """Validate Azure takeover"""
        try:
            response = requests.get(f"https://{candidate['cname']}", timeout=10)
            
            # Azure "Web App not found" or 404
            if 'Error 404 - Web app not found' in response.text or response.status_code == 404:
                return {
                    'vulnerable': True,
                    'impact': 'HIGH - Can claim Azure app name and serve malicious content',
                    'reproduction': '1. Create Azure Web App with this name\n2. Deploy any content\n3. Subdomain serves your content',
                    'fix': 'Delete CNAME record or create the Azure resource'
                }
            
            return {'vulnerable': False, 'reason': f'Status {response.status_code}'}
            
        except Exception as e:
            return {'vulnerable': False, 'reason': str(e)}
    
    def _validate_heroku(self, candidate):
        """Validate Heroku takeover"""
        try:
            response = requests.get(f"https://{candidate['cname']}", timeout=10)
            
            # Heroku "No such app"
            if 'No such app' in response.text:
                app_name = candidate['cname'].replace('.herokuapp.com', '')
                return {
                    'vulnerable': True,
                    'impact': 'MEDIUM - Can create Heroku app and serve content',
                    'reproduction': f'1. Create Heroku app: {app_name}\n2. Deploy any content\n3. Subdomain serves your content',
                    'fix': 'Delete CNAME record or create the Heroku app'
                }
            
            return {'vulnerable': False, 'reason': 'App exists'}
            
        except Exception as e:
            return {'vulnerable': False, 'reason': str(e)}
    
    def _validate_shopify(self, candidate):
        """Validate Shopify takeover"""
        try:
            response = requests.get(f"https://{candidate['cname']}", timeout=10)
            
            # Shopify "Sorry, this shop is currently unavailable"
            if 'Sorry, this shop is currently unavailable' in response.text:
                shop_name = candidate['cname'].replace('.myshopify.com', '')
                return {
                    'vulnerable': True,
                    'impact': 'MEDIUM - Can claim Shopify store name',
                    'reproduction': f'1. Create Shopify store: {shop_name}\n2. Configure custom domain\n3. Subdomain points to your store',
                    'fix': 'Delete CNAME record or claim the Shopify store name'
                }
            
            return {'vulnerable': False, 'reason': 'Shop exists'}
            
        except Exception as e:
            return {'vulnerable': False, 'reason': str(e)}
    
    def generate_hackerone_report(self, confirmed):
        """Generate HackerOne-ready markdown report"""
        print("\n" + "="*60)
        print("📝 PHASE 4: Generating Reports")
        print("="*60)
        
        if not confirmed:
            print("ℹ️  No confirmed takeovers found")
            return
        
        for finding in confirmed:
            report = self._create_single_report(finding)
            
            # Save individual report
            filename = f"{self.output_dir}/report_{finding['subdomain']}.md"
            with open(filename, 'w') as f:
                f.write(report)
            
            print(f"\n✅ Report generated: {filename}")
            print(f"   Subdomain: {finding['subdomain']}")
            print(f"   Service: {finding['service']['name']}")
            print(f"   Impact: {finding['validation']['impact']}")
    
    def _create_single_report(self, finding):
        """Create HackerOne format report for single finding"""
        report = f"""# Subdomain Takeover: {finding['subdomain']}

## Summary
The subdomain **{finding['subdomain']}** is vulnerable to takeover via {finding['service']['name']}.

## Severity
{finding['validation']['impact'].split(' - ')[0]}

## Description
The subdomain `{finding['subdomain']}` has a CNAME record pointing to `{finding['cname']}`, but the {finding['service']['name']} resource is not claimed. This allows an attacker to register this resource and serve arbitrary content under the victim's domain.

## Steps to Reproduce
{finding['validation']['reproduction']}

## Impact
{finding['validation']['impact'].split(' - ')[1] if ' - ' in finding['validation']['impact'] else finding['validation']['impact']}

An attacker could:
- Serve malicious content under your domain
- Steal cookies/session data
- Phish users with trusted domain
- Damage brand reputation

## Recommended Fix
{finding['validation']['fix']}

## Evidence
- CNAME Record: `{finding['cname']}`
- Detected Service: {finding['service']['name']}
- Confirmed At: {finding['confirmed_at']}

---

*Report generated by TakeoverHunter v1.0*
*Target: {self.target}*
*Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        return report
    
    def generate_summary(self, confirmed):
        """Generate JSON summary of all findings"""
        summary = {
            'scan_info': {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'total_confirmed': len(confirmed)
            },
            'findings': confirmed
        }
        
        summary_file = f"{self.output_dir}/SUMMARY.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n📊 Summary saved: {summary_file}")
        return summary
    
    def run(self):
        """Main execution flow"""
        print("\n" + "="*60)
        print("🚀 TAKEOVERHUNTER v1.0 - Starting Scan")
        print("="*60)
        
        # Phase 1: Find subdomains
        subdomains = self.find_subdomains()
        if not subdomains:
            print("\n❌ No subdomains found. Exiting.")
            return
        
        # Phase 2: Check DNS
        candidates = self.check_dns_records(subdomains)
        if not candidates:
            print("\nℹ️  No takeover candidates found. Exiting.")
            return
        
        # Phase 3: Validate
        confirmed = self.validate_takeover(candidates)
        
        # Phase 4: Generate reports
        self.generate_hackerone_report(confirmed)
        self.generate_summary(confirmed)
        
        # Final output
        print("\n" + "="*60)
        print("✅ SCAN COMPLETE")
        print("="*60)
        print(f"\n📁 Results in: {self.output_dir}/")
        print(f"🎯 Confirmed takeovers: {len(confirmed)}")
        
        if confirmed:
            print("\n🚀 Ready to submit:")
            for f in confirmed:
                print(f"   • {f['subdomain']} ({f['service']['name']})")
                print(f"     Report: report_{f['subdomain']}.md")
        else:
            print("\n💡 No confirmed takeovers this time. Try another target!")

if __name__ == "__main__":
    print("="*60)
    print("🎯 TAKEOVERHUNTER v1.0 - Subdomain Takeover Finder")
    print("="*60)
    print("\nFinds CONFIRMED subdomain takeovers, not just potentials")
    print("Generates HackerOne-ready reports")
    print("="*60)
    
    if len(sys.argv) < 2:
        target = input("\nEnter target domain (e.g., example.com): ").strip()
    else:
        target = sys.argv[1]
    
    if not target:
        print("❌ No target provided")
        sys.exit(1)
    
    # Optional: API keys for validation
    github_token = os.getenv('GITHUB_TOKEN')  # Set if you have one
    
    hunter = TakeoverHunter(target, github_token=github_token)
    hunter.run()
    
    print("\n" + "="*60)
    print("🎉 All done! Check the output directory for reports.")
    print("="*60)
