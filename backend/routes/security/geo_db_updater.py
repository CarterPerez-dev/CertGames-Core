import os
import requests
import gzip
import shutil
import tarfile
import schedule
import time
import logging

load_dotenv()

logger = logging.getLogger(__name__)

ASN_DB_PATH = os.path.join(os.environ.get('DB_DIRECTORY')
COUNTRY_DB_PATH = os.path.join(os.environ.get('DB_DIRECTORY')

def download_and_extract_db():
    """Download and extract the latest MaxMind GeoLite2 databases"""
    try:
        # Create directory if it doesn't exist
        if not os.path.exists(DB_DIRECTORY):
            os.makedirs(DB_DIRECTORY)
            
        # Download ASN database
        asn_url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key={LICENSE_KEY}&suffix=tar.gz"
        asn_response = requests.get(asn_url)
        
        if asn_response.status_code == 200:
            asn_tar_path = os.path.join(DB_DIRECTORY, "GeoLite2-ASN.tar.gz")
            with open(asn_tar_path, 'wb') as f:
                f.write(asn_response.content)
                
            # Extract ASN database
            with tarfile.open(asn_tar_path) as tar:
                tar.extractall(path=DB_DIRECTORY)
                
            # Remove tar file
            os.remove(asn_tar_path)
            
            # Find the extracted directory and rename it to a consistent name
            extracted_dir = None
            for item in os.listdir(DB_DIRECTORY):
                if os.path.isdir(os.path.join(DB_DIRECTORY, item)) and item.startswith("GeoLite2-ASN_"):
                    extracted_dir = item
                    break
                    
            if extracted_dir:
                source_path = os.path.join(DB_DIRECTORY, extracted_dir, "GeoLite2-ASN.mmdb")
                dest_path = os.path.join(DB_DIRECTORY, "GeoLite2-ASN.mmdb")
                shutil.copy(source_path, dest_path)
                shutil.rmtree(os.path.join(DB_DIRECTORY, extracted_dir))
                
            logger.info("ASN database updated successfully")
            
        # Download Country database (similar process)
        country_url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={LICENSE_KEY}&suffix=tar.gz"
        # (Similar extraction process as above)
        
        return True
    except Exception as e:
        logger.error(f"Error updating GeoIP databases: {str(e)}")
        return False

# Schedule weekly updates
def start_scheduler():
    schedule.every().monday.at("03:00").do(download_and_extract_db)
    
    # Initial download if databases don't exist
    if not os.path.exists(os.path.join(DB_DIRECTORY, "GeoLite2-ASN.mmdb")):
        download_and_extract_db()
        
    # Run the scheduler
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Check every hour
