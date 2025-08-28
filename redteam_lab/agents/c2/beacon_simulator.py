#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced C2 Beacon Simulator with OPSEC Controls"""

import random
import time
import os
import sys
from typing import List, Optional
from scapy.all import IP, TCP, Raw, send
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/c2_simulator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EncryptedBeacon:
    """AES-256 GCM encrypted beacon payload generator"""
    def __init__(self, key: bytes, nonce: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self.cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )

    def encrypt(self, plaintext: str) -> bytes:
        encryptor = self.cipher.encryptor()
        return encryptor.update(plaintext.encode()) + encryptor.finalize()

class BeaconSimulator:
    """Advanced C2 beacon simulator with OPSEC features"""
    
    def __init__(self, c2_servers: List[str], jitter_range: tuple = (30, 300)):
        """
        Args:
            c2_servers: List of C2 server IPs/Domains
            jitter_range: Min/max beacon delay in seconds
        """
        if not c2_servers:
            raise ValueError("At least one C2 server required")
        
        self.c2_servers = c2_servers
        self.jitter = lambda: random.randint(*jitter_range)
        self.encryptor = EncryptedBeacon(
            key=os.urandom(32),
            nonce=os.urandom(12)
        )
        # OPSEC controls
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.beacon_count = 0
        self.max_beacons = 1000  # Safety limit

    def _generate_payload(self) -> str:
        """Create realistic-looking beacon data"""
        self.beacon_count += 1
        return (
            f"id={random.getrandbits(128):x}&"
            f"data={os.urandom(64).hex()}&"
            f"count={self.beacon_count}&"
            f"ua={self.user_agent}"
        )
    def _send_beacon(self, server: str) -> bool:
        """Send encrypted beacon with network randomization"""
        try:
            payload = self._generate_payload()
            encrypted = self.encryptor.encrypt(payload)
            
            # Randomize source port and TTL
            sport = random.randint(49152, 65535)
            ttl = random.choice([64, 128, 255])
            
            pkt = IP(dst=server, ttl=ttl)/TCP(
                sport=sport,
                dport=443,
                flags="PA"
            )/Raw(load=encrypted)
            
            send(pkt, verbose=0)
            logger.info(f"Beacon #{self.beacon_count} sent to {server}")
            return True
            
        except Exception as e:
            logger.error(f"Beacon failed: {str(e)}")
            return False

    def run(self, duration: Optional[float] = None) -> None:
        """Run beacon loop with optional time limit"""
        start_time = time.time()
        try:
            while True:
                if self.beacon_count >= self.max_beacons:
                    logger.warning("Reached maximum beacon limit")
                    break
                    
                if duration and (time.time() - start_time) > duration:
                    logger.info("Duration limit reached")
                    break
                    
                server = random.choice(self.c2_servers)
                self._send_beacon(server)
                time.sleep(self.jitter())
                
        except KeyboardInterrupt:
            logger.info("Simulation stopped by user")

if __name__ == "__main__":
    # Operational security checks
    if os.geteuid() != 0:
        logger.error("This tool requires root privileges for raw socket access")
        sys.exit(1) 
    if not os.path.exists("/var/log/c2_simulator.log"):
        os.mknod("/var/log/c2_simulator.log", 0o600)
    
    # Example usage
    simulator = BeaconSimulator(
        c2_servers=["192.168.1.100", "10.0.0.15"],
        jitter_range=(45, 600)  # Wider jitter window
    )
    
    logger.info("Starting C2 beacon simulation (Ctrl+C to stop)")
    simulator.run(duration=3600)  # 1 hour duration