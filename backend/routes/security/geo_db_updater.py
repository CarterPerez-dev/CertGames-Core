# /app/routes/security/geo_db_updater.py

import os
import requests
import shutil
import tarfile
import time
import logging
from dotenv import load_dotenv


load_dotenv()


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


DB_DIRECTORY = os.environ.get('DB_DIRECTORY')
LICENSE_KEY = os.environ.get('MAXMIND_LICENSE_KEY')

if not DB_DIRECTORY:
    logger.critical("FATAL: DB_DIRECTORY environment variable not set.")
    raise ValueError("DB_DIRECTORY environment variable is required but not set.")

if not LICENSE_KEY:
    logger.critical("FATAL: MAXMIND_LICENSE_KEY environment variable not set.")
    raise ValueError("MAXMIND_LICENSE_KEY environment variable is required but not set.")



geoip_dir = os.environ.get('DB_DIRECTORY', '/app/geoip_db')

# Complete the paths with proper filenames
ASN_DB_PATH = os.path.join(geoip_dir, 'GeoLite2-ASN.mmdb')
COUNTRY_DB_PATH = os.path.join(geoip_dir, 'GeoLite2-Country.mmdb')


def download_and_extract_db():
    """
    Downloads and extracts the latest MaxMind GeoLite2 ASN and Country databases.
    Returns True if both databases are updated successfully, False otherwise.
    """
    logger.info("Starting GeoIP database update process...")
    success = True # Assume success initially

    databases_to_update = [
        {"edition_id": "GeoLite2-ASN", "final_path": ASN_DB_PATH},
        {"edition_id": "GeoLite2-Country", "final_path": COUNTRY_DB_PATH},
    ]

    for db_info in databases_to_update:
        edition_id = db_info["edition_id"]
        final_db_path = db_info["final_path"]
        db_filename = os.path.basename(final_db_path) # e.g., "GeoLite2-ASN.mmdb"
        tar_filename = f"{edition_id}.tar.gz"
        tar_path = os.path.join(DB_DIRECTORY, tar_filename)

        logger.info(f"--- Processing {edition_id} ---")

        try:
            # 1. Download
            logger.info(f"Downloading {edition_id} database...")
            url = f"https://download.maxmind.com/app/geoip_download?edition_id={edition_id}&license_key={LICENSE_KEY}&suffix=tar.gz"
            response = requests.get(url, stream=True, timeout=60) # Use stream and add timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            logger.info(f"Saving temporary archive to {tar_path}")
            with open(tar_path, 'wb') as f:
                shutil.copyfileobj(response.raw, f)
            del response # Free up memory

            # 2. Extract
            logger.info(f"Extracting {db_filename} from {tar_path}...")
            extracted = False
            with tarfile.open(tar_path, "r:gz") as tar:
                mmdb_member = None
                expected_suffix = f"/{db_filename}" # e.g., "/GeoLite2-ASN.mmdb"

                # Find the correct .mmdb file within the tar archive's directory structure
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith(expected_suffix):
                        mmdb_member = member
                        break # Found the file

                if mmdb_member:
                    # Extract *only* the mmdb file to a temporary location first
                    # to handle potential directory structure inside tar
                    temp_extract_path = os.path.join(DB_DIRECTORY, mmdb_member.name)
                    logger.debug(f"Extracting member {mmdb_member.name} to {os.path.dirname(temp_extract_path)}")
                    tar.extract(mmdb_member, path=DB_DIRECTORY)

                    # Move the extracted file to the final destination, overwriting if necessary
                    logger.info(f"Moving extracted file {temp_extract_path} to {final_db_path}")
                    shutil.move(temp_extract_path, final_db_path)
                    extracted = True

                    # Attempt to remove the (now likely empty) directory created by extraction
                    extracted_dir_path = os.path.dirname(temp_extract_path)
                    if extracted_dir_path != DB_DIRECTORY: # Avoid trying to remove DB_DIRECTORY itself
                        try:
                            if not os.listdir(extracted_dir_path): # Check if empty
                                logger.debug(f"Removing empty extracted directory: {extracted_dir_path}")
                                os.rmdir(extracted_dir_path)
                            else:
                                logger.warning(f"Extracted directory {extracted_dir_path} was not empty after moving .mmdb file. Manual cleanup might be needed.")
                        except OSError as e:
                            logger.warning(f"Could not remove temporary directory {extracted_dir_path}: {e}")
                else:
                    logger.error(f"Could not find {db_filename} within the downloaded archive {tar_path}.")
                    success = False # Mark failure for this DB

            # 3. Cleanup Tar File
            if os.path.exists(tar_path):
                 logger.info(f"Removing temporary archive {tar_path}")
                 os.remove(tar_path)

            if extracted:
                logger.info(f"{edition_id} database updated successfully.")
            else:
                # Error already logged if not extracted, ensure overall success is False
                success = False


        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading {edition_id} database: {e}")
            success = False
        except tarfile.TarError as e:
            logger.error(f"Error extracting {edition_id} database from {tar_path}: {e}")
            success = False
        except OSError as e:
            logger.error(f"File system error during {edition_id} update: {e}")
            success = False
        except Exception as e:
            logger.error(f"An unexpected error occurred during {edition_id} update: {e}", exc_info=True)
            success = False
        finally:
            # Ensure tar file is removed even if extraction failed mid-way but download succeeded
             if os.path.exists(tar_path):
                 try:
                     logger.debug(f"Ensuring removal of temporary archive {tar_path} after process")
                     os.remove(tar_path)
                 except OSError as e:
                     logger.warning(f"Could not remove temporary archive {tar_path} during cleanup: {e}")

        if not success:
            logger.error(f"Update process failed for {edition_id}.")


    if success:
         logger.info("GeoIP database update process completed successfully for all requested databases.")
    else:
         logger.error("GeoIP database update process finished with one or more failures.")

    return success




