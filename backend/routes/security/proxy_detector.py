import requests
import threading
import time
import json
import os
import logging
from datetime import datetime, timedelta
import ipaddress

logger = logging.getLogger(__name__)

class ProxyDetector:
    def __init__(self, cache_dir=None):
        # Use environment variable with fallback
        self.cache_dir = cache_dir or os.environ.get('PROXY_CACHE_PATH') # .env variable for /pathtp/proxy_cache_path
        self.tor_exit_nodes = set()
        self.known_proxies = set()
        self.last_update = datetime.utcnow() - timedelta(days=1)  
        self.update_lock = threading.Lock()
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
            
        # Load cached data if available
        self._load_cached_data()
        
        # Start background updater thread
        self._start_updater()
        
    def _load_cached_data(self):
        """Load cached proxy and Tor node data"""
        try:
            tor_cache_path = os.path.join(self.cache_dir, "tor_nodes.json")
            if os.path.exists(tor_cache_path):
                with open(tor_cache_path, 'r') as f:
                    data = json.load(f)
                    self.tor_exit_nodes = set(data.get("nodes", []))
                    last_update = data.get("last_update")
                    if last_update:
                        self.last_update = datetime.fromisoformat(last_update)
            
            proxy_cache_path = os.path.join(self.cache_dir, "proxies.json")
            if os.path.exists(proxy_cache_path):
                with open(proxy_cache_path, 'r') as f:
                    data = json.load(f)
                    self.known_proxies = set(data.get("proxies", []))
                    
            logger.info(f"Loaded {len(self.tor_exit_nodes)} Tor nodes and {len(self.known_proxies)} proxies from cache")
        except Exception as e:
            logger.error(f"Error loading cached proxy data: {str(e)}")
    
    def _save_cached_data(self):
        """Save current proxy and Tor node data to disk"""
        try:
            # Save Tor nodes
            tor_cache_path = os.path.join(self.cache_dir, "tor_nodes.json")
            with open(tor_cache_path, 'w') as f:
                json.dump({
                    "nodes": list(self.tor_exit_nodes),
                    "last_update": self.last_update.isoformat()
                }, f)
                
            # Save proxies
            proxy_cache_path = os.path.join(self.cache_dir, "proxies.json")
            with open(proxy_cache_path, 'w') as f:
                json.dump({
                    "proxies": list(self.known_proxies)
                }, f)
                
            logger.info("Saved proxy and Tor data to cache")
        except Exception as e:
            logger.error(f"Error saving cached proxy data: {str(e)}")
    
    def _update_lists(self):
        """Update Tor exit node and proxy lists"""
        with self.update_lock:
            now = datetime.utcnow()
            # Only update if it's been more than 6 hours
            if (now - self.last_update) < timedelta(hours=6):
                return
                
            try:
                # Update Tor exit node list from Tor Project
                tor_response = requests.get("https://check.torproject.org/exit-addresses", timeout=10)
                if tor_response.status_code == 200:
                    new_nodes = set()
                    for line in tor_response.text.split("\n"):
                        if line.startswith("ExitAddress "):
                            parts = line.split()
                            if len(parts) >= 2:
                                new_nodes.add(parts[1])
                    
                    # Only update if we got a reasonable number of nodes
                    if len(new_nodes) > 50:
                        self.tor_exit_nodes = new_nodes
                        logger.info(f"Updated Tor exit node list, found {len(new_nodes)} nodes")
                
                # Also try dan.me.uk as an alternative source
                try:
                    dan_response = requests.get("https://www.dan.me.uk/torlist/", timeout=10)
                    if dan_response.status_code == 200:
                        for line in dan_response.text.split("\n"):
                            ip = line.strip()
                            if ip and is_valid_ip(ip):
                                self.tor_exit_nodes.add(ip)
                except Exception as e:
                    logger.warning(f"Error getting Tor list from dan.me.uk: {str(e)}")
                
                
                # Public proxy list
                
                try:
                    proxy_response = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", timeout=10)
                    if proxy_response.status_code == 200:
                        for line in proxy_response.text.split("\n"):
                            if ":" in line:
                                ip = line.split(":")[0].strip()
                                if ip and is_valid_ip(ip):
                                    self.known_proxies.add(ip)
                except Exception as e:
                    logger.warning(f"Error getting proxy list: {str(e)}")
                
                # Update timestamp and save to cache
                self.last_update = now
                self._save_cached_data()
                
            except Exception as e:
                logger.error(f"Error updating proxy lists: {str(e)}")
    
    def _start_updater(self):
        """Start the background updater thread"""
        def updater_thread():
            while True:
                try:
                    self._update_lists()
                    # Sleep for 2 hours
                    time.sleep(7200)
                except Exception as e:
                    logger.error(f"Error in updater thread: {str(e)}")
                    time.sleep(300)  # Sleep for 5 minutes on error
        
        thread = threading.Thread(target=updater_thread, daemon=True)
        thread.start()
        
    def is_tor_exit_node(self, ip):
        """Check if the given IP is a Tor exit node"""
        # Trigger an update if needed
        if (datetime.utcnow() - self.last_update) > timedelta(hours=12):
            self._update_lists()
            
        return ip in self.tor_exit_nodes
        
    def is_known_proxy(self, ip):
        """Check if the given IP is a known proxy"""
        # This one is less reliable with just free data
        return ip in self.known_proxies
        
    def is_tor_or_proxy(self, ip):
        """Check if the given IP is either a Tor exit node or a known proxy"""
        return self.is_tor_exit_node(ip) or self.is_known_proxy(ip)

def is_valid_ip(ip):
    """Check if the given string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Global instance
proxy_detector = ProxyDetector()
