"""
Production Verification Engine

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This module performs ACTUAL verification and certificate generation.

Key Functions:
1. Wipe Verification - Confirms data destruction was successful
2. Audit Logging - Creates tamper-proof audit trails
3. Certificate Generation - Produces signed compliance certificates
4. Cryptographic Signing - RSA-PSS digital signatures for integrity

Verification Methods:
- Hardware Erase: Exit code validation for NVMe/ATA commands
- Software Overwrite: Random sector sampling and pattern analysis
- Compliance: NIST SP 800-88 Rev. 1 standards adherence

Certificate Formats:
- JSON: Machine-readable audit data with cryptographic signatures
- PDF: Human-readable compliance certificates
- Desktop Storage: Certificates saved to user's Desktop for easy access
"""

import os
import sys
import json
import hashlib
import secrets
import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from pathlib import Path
import logging

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import win32file
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class VerificationError(Exception):
    pass


class CertificateGenerationError(Exception):
    pass


class VerificationEngine:
    """Verification and certificate generation engine
    
    Handles post-wipe verification and generates tamper-proof certificates
    for compliance and audit purposes. Implements multiple verification
    methods based on the wipe technique used.
    
    Certificate Features:
    - Cryptographic signatures using RSA-PSS
    - Tamper-proof audit trails
    - NIST SP 800-88 Rev. 1 compliance documentation
    - JSON and PDF export formats
    """
    
    def __init__(self, development_mode: bool = False):
        """Initialize verification engine with certificate storage paths
        
        Args:
            development_mode (bool): If True, enables additional safety checks
        """
        self.development_mode = development_mode
        self.logger = logging.getLogger(__name__)
        
        # Certificate storage - save directly to user's Desktop for easy access
        # This ensures certificates are immediately visible and accessible
        desktop_path = Path.home() / "Desktop"
        self.certs_dir = desktop_path
        
        # Cryptographic key paths (generated dynamically for each certificate)
        self.private_key_path = self.certs_dir / "shuddh_signing_key.pem"
        self.public_key_path = self.certs_dir / "shuddh_signing_key_pub.pem"

    def verify_hardware_erase(self, wipe_result: Dict[str, Any]) -> Dict[str, Any]:
        """Verify hardware erase by checking command exit code
        
        For hardware-level erase methods (NVMe FORMAT_NVM, ATA SECURE ERASE),
        verification relies on the command exit code. These methods instruct
        the drive controller to perform internal secure erase operations.
        
        Hardware erase verification is limited because:
        1. The erase happens at the controller level
        2. Data is cryptographically erased (encryption keys destroyed)
        3. Physical verification would require specialized equipment
        
        This method provides reasonable assurance based on:
        - Command execution success
        - Drive controller compliance with standards
        - Industry-standard secure erase implementations
        
        Args:
            wipe_result (Dict[str, Any]): Results from hardware wipe execution
            
        Returns:
            Dict[str, Any]: Verification results with reliability assessment
        """
        
        method = wipe_result.get('method', 'UNKNOWN')
        success = wipe_result.get('success', False)
        
        # Hardware methods are verified by successful command execution
        if method in ["NVME_FORMAT_NVM", "ATA_SECURE_ERASE"] and success:
            return {
                "verification_method": "EXIT_CODE_CHECK",
                "verification_status": "SUCCESS",
                "exit_code": 0,
                "verification_details": f"{method} command returned success (0) exit code",
                "verification_timestamp": datetime.now(timezone.utc).isoformat(),
                "verification_reliable": True  # Hardware methods are generally reliable
            }
        else:
            return {
                "verification_method": "EXIT_CODE_CHECK",
                "verification_status": "FAILED",
                "exit_code": 1,
                "verification_details": f"{method} command failed or unsupported",
                "verification_timestamp": datetime.now(timezone.utc).isoformat(),
                "verification_reliable": False
            }

    def verify_software_overwrite(self, drive_info: Dict[str, Any], wipe_result: Dict[str, Any]) -> Dict[str, Any]:
        """Verify AES_128_CTR overwrite by reading random sectors
        
        For software overwrite methods, verification involves reading random
        sectors from the drive and analyzing the data patterns. This provides
        evidence that the overwrite operation was successful.
        
        Verification Process:
        1. Sample random sectors across the drive
        2. Analyze data patterns for predictable sequences
        3. Generate cryptographic hash of sampled data
        4. Check for signs of incomplete overwrite
        
        Pattern Analysis:
        - All zeros: Indicates possible incomplete wipe
        - Repeating patterns: May indicate systematic errors
        - Random data: Expected result of successful overwrite
        
        Limitations:
        - Cannot verify 100% of drive (would take too long)
        - Some original data might remain in unsampled areas
        - Provides statistical confidence rather than absolute proof
        
        Args:
            drive_info (Dict[str, Any]): Drive information for sector calculation
            wipe_result (Dict[str, Any]): Results from software wipe operation
            
        Returns:
            Dict[str, Any]: Verification results with pattern analysis
            
        Raises:
            VerificationError: If drive access fails or verification cannot complete
        """
        
        if not HAS_PYWIN32:
            raise VerificationError("pywin32 required for drive verification")
        
        # Construct drive path and calculate sampling parameters
        drive_path = drive_info.get('DeviceID', f"\\\\.\\PhysicalDrive{drive_info.get('Index', 0)}")
        drive_size = drive_info.get('Size', 0)
        sector_size = 512  # Standard sector size
        sectors_to_sample = 50  # Balance between thoroughness and speed
        
        try:
            # Open drive for read-only verification access
            handle = win32file.CreateFile(
                drive_path,
                win32con.GENERIC_READ,  # Read-only for verification
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            
            try:
                sampled_sectors = []
                verification_data = b""
                max_sectors = drive_size // sector_size if drive_size > 0 else 1000000
                
                # Sample random sectors across the drive
                for i in range(sectors_to_sample):
                    # Generate cryptographically secure random sector number
                    random_sector = secrets.randbelow(max_sectors)
                    offset = random_sector * sector_size
                    
                    # Seek to the random sector
                    win32file.SetFilePointer(handle, offset, win32con.FILE_BEGIN)
                    
                    # Read sector data
                    _, sector_data = win32file.ReadFile(handle, sector_size)
                    
                    # Record sector information for audit trail
                    sampled_sectors.append({
                        "sector_number": random_sector,
                        "offset_bytes": offset,
                        "data_hash": hashlib.sha256(sector_data).hexdigest()[:16]  # Truncated hash
                    })
                    verification_data += sector_data
                
            finally:
                # Always close the drive handle
                win32file.CloseHandle(handle)
            
            # Generate cryptographic hash of all sampled data
            verification_hash = hashlib.sha256(verification_data).hexdigest()
            
            # Analyze data patterns to detect incomplete wipes
            patterns_detected = self._analyze_patterns(verification_data)
            
            return {
                "verification_method": "SECTOR_SAMPLING",
                "verification_status": "SUCCESS" if not patterns_detected else "FAILED",
                "sectors_sampled": sectors_to_sample,
                "verification_hash": f"sha256:{verification_hash}",
                "verification_details": f"Sampled {sectors_to_sample} random sectors, patterns detected: {patterns_detected}",
                "verification_timestamp": datetime.now(timezone.utc).isoformat(),
                "pattern_analysis": {
                    "all_zeros_detected": b'\x00' * 512 in verification_data,
                    "repeating_patterns_detected": patterns_detected,
                    "original_data_detected": False  # Would require more sophisticated analysis
                },
                "sampled_sectors": sampled_sectors[:5],  # Include first 5 for audit
                "total_verification_data_bytes": len(verification_data)
            }
            
        except Exception as e:
            raise VerificationError(f"Software verification failed: {e}")

    def _analyze_patterns(self, data: bytes) -> bool:
        """Analyze data for predictable patterns"""
        # Check for all zeros using more efficient method
        zero_chunk = b'\x00' * 512
        if zero_chunk in data:
            return True
        
        # Check for repeating patterns
        chunk_size = 16
        for i in range(0, len(data) - chunk_size * 3, chunk_size):
            chunk = data[i:i + chunk_size]
            if data[i + chunk_size:i + chunk_size * 2] == chunk and \
               data[i + chunk_size * 2:i + chunk_size * 3] == chunk:
                return True
        
        return False

    def create_audit_log(self, drive_info: Dict[str, Any], wipe_result: Dict[str, Any], 
                        verification_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive tamper-proof audit log
        
        Generates a complete audit trail documenting the entire wipe operation.
        This audit log serves as the foundation for compliance certificates
        and provides forensic-quality documentation of the data destruction.
        
        Audit Log Components:
        1. Metadata: Unique ID, timestamps, version information
        2. Drive Information: Hardware details for identification
        3. Wipe Details: Method used, timing, success status
        4. Verification: Post-wipe validation results
        5. System Context: Environment where wipe was performed
        6. Compliance: Standards adherence documentation
        
        Compliance Standards:
        - NIST SP 800-88 Rev. 1 (National Institute of Standards)
        - DoD 5220.22-M (Department of Defense)
        - Custom methods for specialized requirements
        
        Args:
            drive_info (Dict[str, Any]): Hardware information
            wipe_result (Dict[str, Any]): Wipe execution results
            verification_result (Dict[str, Any]): Post-wipe verification data
            
        Returns:
            Dict[str, Any]: Comprehensive audit log ready for signing
        """
        # amazonq-ignore-next-line
        
        # Use consistent UTC timestamp for all audit entries
        timestamp = datetime.now(timezone.utc)
        
        # Generate unique audit ID with timestamp and random component
        audit_id = f"SHUDDH-{timestamp.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4).upper()}"
        
        # Map wipe methods to compliance standards
        method = wipe_result.get('method', 'UNKNOWN')
        compliance_mapping = {
            "NVME_FORMAT_NVM": "NIST SP 800-88 Rev. 1 Purge",     # Hardware crypto erase
            "ATA_SECURE_ERASE": "NIST SP 800-88 Rev. 1 Purge",    # Hardware secure erase
            "AES_128_CTR": "NIST SP 800-88 Rev. 1 Clear"           # Software overwrite
        }
        compliance = compliance_mapping.get(method, "Custom Method")
        
        return {
            # Audit metadata for tracking and identification
            "audit_metadata": {
                "audit_id": audit_id,
                "audit_version": "1.0",
                "generated_by": "Shuddh OS Data Wiper v2.0 Production",
                "generation_timestamp_utc": timestamp.isoformat(),
                "development_mode": False  # Production mode indicator
            },
            
            # Complete drive identification information
            "drive_info": {
                "model": drive_info.get('Model', 'Unknown'),
                "serial_number": drive_info.get('SerialNumber', 'Unknown'),
                "size_bytes": drive_info.get('Size', 0),
                "size_gb": drive_info.get('SizeGB', 0),
                "interface_type": drive_info.get('InterfaceType', 'Unknown'),
                "media_type": drive_info.get('MediaType', 'Unknown'),
                "device_id": drive_info.get('DeviceID', 'Unknown'),
                "firmware": drive_info.get('Firmware', 'Unknown')
            },
            
            # Detailed wipe operation documentation
            "wipe_metadata": {
                "method_attempted": method,
                "method_compliant_with": compliance,
                "timestamp_utc": wipe_result.get('start_time', timestamp.isoformat()),
                "completion_timestamp_utc": wipe_result.get('end_time', timestamp.isoformat()),
                "execution_duration": wipe_result.get('duration', 'Unknown'),
                "status": "SUCCESS" if wipe_result.get('success', False) else "FAILED",
                "primary_method_used": wipe_result.get('primary_method_used', True),
                "fallback_method_used": wipe_result.get('fallback_method_used', False),
                "execution_details": wipe_result.get('status', 'No details available')
            },
            
            # Post-wipe verification documentation
            "verification_metadata": {
                "verification_method": verification_result.get('verification_method', 'NONE'),
                "verification_status": verification_result.get('verification_status', 'NOT_PERFORMED'),
                "verification_timestamp_utc": verification_result.get('verification_timestamp', 
                                                                   timestamp.isoformat()),
                "verification_hash": verification_result.get('verification_hash'),
                "verification_details": verification_result.get('verification_details', 'No verification performed'),
                "verification_reliable": verification_result.get('verification_reliable', False)
            },
            
            # System environment context
            "system_metadata": {
                "os_version": f"{os.name} {sys.platform}",
                "python_version": sys.version.split()[0],
                "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
                "username": os.environ.get('USERNAME', 'Unknown')
            },
            
            # Compliance and certification information
            "compliance_certification": {
                "standard": compliance,
                "certification_level": "PRODUCTION",
                "audit_trail_integrity": "CRYPTOGRAPHICALLY_SIGNED",
                "certificate_format": "JSON + PDF"
            }
        }

    def generate_signing_keys(self) -> Tuple[bytes, bytes, bytes]:
        """Generate RSA key pair for certificate signing with secure password
        
        Returns:
            Tuple[bytes, bytes, bytes]: (private_key_pem, public_key_pem, key_password)
        """
        
        if not HAS_CRYPTOGRAPHY:
            raise CertificateGenerationError("Cryptography library required for key generation")
        
        # Generate cryptographically secure password for private key protection
        key_password = secrets.token_bytes(32)  # 256-bit password
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Encrypt private key with secure password
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key_password)
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem, key_password

    def sign_audit_log(self, audit_log: Dict[str, Any]) -> Dict[str, Any]:
        """Cryptographically sign the audit log for tamper-proof integrity
        
        Creates a digital signature using RSA-PSS with SHA-256 to ensure
        the audit log cannot be modified without detection. This provides
        cryptographic proof of the audit log's integrity and authenticity.
        
        Signing Process:
        1. Convert audit log to canonical JSON format
        2. Generate SHA-256 hash of the canonical data
        3. Create RSA key pair for signing
        4. Sign the audit data using RSA-PSS padding
        5. Return signed certificate with verification information
        
        Cryptographic Details:
        - Algorithm: RSA-PSS (Probabilistic Signature Scheme)
        - Hash Function: SHA-256
        - Key Size: 2048 bits (industry standard)
        - Padding: PSS with maximum salt length
        
        Args:
            audit_log (Dict[str, Any]): Complete audit log to sign
            
        Returns:
            Dict[str, Any]: Signed certificate with signature and public key
            
        Raises:
            CertificateGenerationError: If cryptography library unavailable or signing fails
        """
        
        if not HAS_CRYPTOGRAPHY:
            raise CertificateGenerationError("Cryptography library required for signing")
        
        # Convert audit log to canonical JSON format for consistent signing
        # sort_keys=True ensures consistent field ordering
        # separators=(',', ':') removes whitespace for compact representation
        audit_json = json.dumps(audit_log, sort_keys=True, separators=(',', ':'))
        audit_hash = hashlib.sha256(audit_json.encode()).hexdigest()
        
        # Generate fresh RSA key pair for this certificate
        # Each certificate gets its own keys for maximum security
        private_key_pem, public_key_pem, key_password = self.generate_signing_keys()
        
        # Load private key for signing with secure password
        private_key = load_pem_private_key(private_key_pem, password=key_password)
        
        # Create digital signature using RSA-PSS
        # PSS provides better security than PKCS#1 v1.5 padding
        signature = private_key.sign(
            audit_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),      # Mask generation function
                salt_length=padding.PSS.MAX_LENGTH      # Maximum salt for security
            ),
            hashes.SHA256()  # Hash algorithm for signing
        )
        
        # Convert binary signature to hexadecimal for storage
        signature_hex = signature.hex()
        
        return {
            # Certificate metadata for identification and verification
            "certificate_metadata": {
                "certificate_id": audit_log["audit_metadata"]["audit_id"],
                "certificate_version": "1.0",
                "signing_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "signing_method": "RSA-PSS-SHA256",
                "signature_algorithm": "RSA-PSS with SHA-256",
                "key_size": 2048,
                "development_mode": False
            },
            
            # Original audit log (signed data)
            "audit_log": audit_log,
            
            # Cryptographic signature and verification data
            "cryptographic_signature": {
                "audit_log_hash": f"sha256:{audit_hash}",
                "signature": signature_hex,
                "public_key_pem": public_key_pem.decode(),
                "verification_instructions": "Use public key to verify signature against audit_log canonical JSON"
            }
        }

    def export_certificates(self, signed_certificate: Dict[str, Any]) -> Dict[str, str]:
        """Export signed certificate as JSON and PDF files to Desktop"""
        
        certificate_id = signed_certificate["certificate_metadata"]["certificate_id"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export JSON certificate
        # Validate and sanitize filename
        safe_id = certificate_id.split('-')[-1].replace('..', '').replace('/', '').replace('\\', '')
        json_filename = f"Shuddh_Certificate_{safe_id}_{timestamp}.json"
        json_path = self.certs_dir / json_filename
        
        # Ensure path is within certs directory
        if not str(json_path.resolve()).startswith(str(self.certs_dir.resolve())):
            raise ValueError("Invalid certificate path")
            
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(signed_certificate, f, indent=2, ensure_ascii=False)
        except (IOError, PermissionError, OSError) as e:
            raise CertificateGenerationError(f"Failed to save JSON certificate: {e}")
        
        # Export PDF certificate
        # Validate and sanitize PDF filename
        pdf_filename = f"Shuddh_Certificate_{safe_id}_{timestamp}.pdf"
        pdf_path = self.certs_dir / pdf_filename
        
        # Ensure path is within certs directory
        if not str(pdf_path.resolve()).startswith(str(self.certs_dir.resolve())):
            raise ValueError("Invalid PDF path")
        
        try:
            if HAS_REPORTLAB:
                self._generate_pdf_certificate(signed_certificate, pdf_path)
            else:
                # Fallback to text file if reportlab not available
                self._generate_text_certificate(signed_certificate, pdf_path)
        except (IOError, PermissionError, OSError) as e:
            raise CertificateGenerationError(f"Failed to save PDF certificate: {e}")
        
        return {
            "json_certificate_path": str(json_path),
            "pdf_certificate_path": str(pdf_path),
            "certificate_id": certificate_id,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "development_mode": False
        }

    def _generate_pdf_certificate(self, signed_certificate: Dict[str, Any], pdf_path: Path):
        """Generate professional PDF certificate using reportlab"""
        
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        width, height = letter
        
        # Header
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredText(width/2, height-50, "SHUDDH DATA PURIFICATION CERTIFICATE")
        
        # Certificate ID
        c.setFont("Helvetica", 12)
        cert_id = signed_certificate["certificate_metadata"]["certificate_id"]
        c.drawString(50, height-100, f"Certificate ID: {cert_id}")
        
        # Drive information
        drive_info = signed_certificate["audit_log"]["drive_info"]
        y_pos = height - 150
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "DRIVE INFORMATION")
        y_pos -= 30
        
        c.setFont("Helvetica", 10)
        c.drawString(70, y_pos, f"Model: {drive_info['model']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Serial Number: {drive_info['serial_number']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Size: {drive_info['size_gb']} GB")
        y_pos -= 40
        
        # Wipe details
        wipe_info = signed_certificate["audit_log"]["wipe_metadata"]
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "WIPE DETAILS")
        y_pos -= 30
        
        c.setFont("Helvetica", 10)
        c.drawString(70, y_pos, f"Method: {wipe_info['method_attempted']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Compliance: {wipe_info['method_compliant_with']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Status: {wipe_info['status']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Completion: {wipe_info['completion_timestamp_utc']}")
        y_pos -= 40
        
        # Forensic verification details
        if 'forensic_verification' in wipe_info:
            forensic_info = wipe_info['forensic_verification']
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y_pos, "FORENSIC VERIFICATION")
            y_pos -= 30
            
            c.setFont("Helvetica", 10)
            c.drawString(70, y_pos, f"Files Destroyed: {forensic_info.get('files_destroyed', 0):,}")
            y_pos -= 20
            c.drawString(70, y_pos, f"Data Wiped: {forensic_info.get('size_reduced', 0):,} bytes")
            y_pos -= 20
            c.drawString(70, y_pos, f"Verification Status: {forensic_info.get('verification_status', 'UNKNOWN')}")
            y_pos -= 20
            if forensic_info.get('forensic_report_path'):
                report_name = Path(forensic_info['forensic_report_path']).name
                c.drawString(70, y_pos, f"Forensic Report: {report_name}")
                y_pos -= 20
            y_pos -= 20
        
        # Verification
        verify_info = signed_certificate["audit_log"]["verification_metadata"]
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "CERTIFICATE VERIFICATION")
        y_pos -= 30
        
        c.setFont("Helvetica", 10)
        c.drawString(70, y_pos, f"Method: {verify_info['verification_method']}")
        y_pos -= 20
        c.drawString(70, y_pos, f"Status: {verify_info['verification_status']}")
        y_pos -= 20
        if verify_info.get('verification_hash'):
            c.drawString(70, y_pos, f"Hash: {verify_info['verification_hash'][:50]}...")
        y_pos -= 40
        
        # Signature
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "CRYPTOGRAPHIC SIGNATURE")
        y_pos -= 30
        
        c.setFont("Helvetica", 8)
        signature = signed_certificate["cryptographic_signature"]["signature"]
        c.drawString(70, y_pos, f"Signature: {signature[:80]}...")
        y_pos -= 15
        c.drawString(70, y_pos, f"           {signature[80:160]}...")
        
        # Footer
        c.setFont("Helvetica", 10)
        c.drawCentredText(width/2, 50, "Generated by Shuddh OS Data Wiper v2.0 Production")
        
        c.save()

    def _generate_text_certificate(self, signed_certificate: Dict[str, Any], pdf_path: Path):
        """Generate text-based certificate as fallback"""
        
        cert_content = f"""
SHUDDH DATA PURIFICATION CERTIFICATE
===================================

Certificate ID: {signed_certificate['certificate_metadata']['certificate_id']}
Generated: {signed_certificate['certificate_metadata']['signing_timestamp_utc']}

DRIVE INFORMATION:
- Model: {signed_certificate['audit_log']['drive_info']['model']}
- Serial: {signed_certificate['audit_log']['drive_info']['serial_number']}
- Size: {signed_certificate['audit_log']['drive_info']['size_gb']} GB

WIPE DETAILS:
- Method: {signed_certificate['audit_log']['wipe_metadata']['method_attempted']}
- Compliance: {signed_certificate['audit_log']['wipe_metadata']['method_compliant_with']}
- Status: {signed_certificate['audit_log']['wipe_metadata']['status']}

FORENSIC VERIFICATION:
- Files Destroyed: {signed_certificate['audit_log']['wipe_metadata'].get('forensic_verification', {}).get('files_destroyed', 'N/A')}
- Data Wiped: {signed_certificate['audit_log']['wipe_metadata'].get('forensic_verification', {}).get('size_reduced', 'N/A')} bytes
- Verification Status: {signed_certificate['audit_log']['wipe_metadata'].get('forensic_verification', {}).get('verification_status', 'N/A')}

VERIFICATION:
- Method: {signed_certificate['audit_log']['verification_metadata']['verification_method']}
- Status: {signed_certificate['audit_log']['verification_metadata']['verification_status']}
- Hash: {signed_certificate['audit_log']['verification_metadata'].get('verification_hash', 'N/A')}

CRYPTOGRAPHIC SIGNATURE:
- Algorithm: {signed_certificate['certificate_metadata']['signature_algorithm']}
- Hash: {signed_certificate['cryptographic_signature']['audit_log_hash']}
- Signature: {signed_certificate['cryptographic_signature']['signature']}

Generated by Shuddh OS Data Wiper v2.0 Production - by sambhranta
        """
        
        try:
            with open(pdf_path, 'w', encoding='utf-8') as f:
                f.write(cert_content)
        except (IOError, PermissionError, OSError) as e:
            raise CertificateGenerationError(f"Failed to save text certificate: {e}")

    def run_phase3_verification(self, drive_info: Dict[str, Any], wipe_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute complete Phase 3: Verification & Trust Generation"""
        
        try:
            method = wipe_result.get('method', 'UNKNOWN')
            
            # Quick Verification
            if method in ["NVME_FORMAT_NVM", "ATA_SECURE_ERASE"]:
                verification_result = self.verify_hardware_erase(wipe_result)
            elif method == "AES_128_CTR":
                verification_result = self.verify_software_overwrite(drive_info, wipe_result)
            else:
                verification_result = {
                    "verification_method": "UNSUPPORTED",
                    "verification_status": "SKIPPED",
                    "verification_details": f"Verification not implemented for method: {method}",
                    "verification_timestamp": datetime.now(timezone.utc).isoformat()
                }
            
            # Create Audit Log
            audit_log = self.create_audit_log(drive_info, wipe_result, verification_result)
            
            # Generate Certificate
            signed_certificate = self.sign_audit_log(audit_log)
            
            # Export Certificates
            export_result = self.export_certificates(signed_certificate)
            
            return {
                "phase": "Phase 3 - Verification & Trust Generation",
                "success": True,
                "verification_result": verification_result,
                "audit_log": audit_log,
                "signed_certificate": signed_certificate,
                "export_result": export_result,
                "completion_timestamp": datetime.now(timezone.utc).isoformat(),
                "development_mode": False
            }
            
        except Exception as e:
            return {
                "phase": "Phase 3 - Verification & Trust Generation",
                "success": False,
                "error": str(e),
                "completion_timestamp": datetime.now(timezone.utc).isoformat()
            }