import json
import base64
import requests
from datetime import datetime, timedelta
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class AppleReceiptVerifier:
    """
    Utility class for verifying Apple In-App Purchase receipts
    """
    
    # Sandbox and production URLs
    SANDBOX_URL = "https://sandbox.itunes.apple.com/verifyReceipt"
    PRODUCTION_URL = "https://buy.itunes.apple.com/verifyReceipt"
    
    def __init__(self, shared_secret=None):
        """
        Initialize the verifier with your app's shared secret (optional)
        """
        self.shared_secret = shared_secret
        
    def verify_receipt(self, receipt_data, sandbox_mode=False):
        """
        Verify an Apple receipt
        
        Args:
            receipt_data (str): The base64 encoded receipt data
            sandbox_mode (bool): Whether to test in sandbox mode first
            
        Returns:
            dict: The verification result with status and receipt info
        """
        try:
            # First try production environment
            verification_url = self.PRODUCTION_URL if not sandbox_mode else self.SANDBOX_URL
            
            # Prepare request data
            request_data = {"receipt-data": receipt_data}
            if self.shared_secret:
                request_data["password"] = self.shared_secret
                
            # Send verification request
            response = requests.post(
                verification_url,
                json=request_data,
                headers={"Content-Type": "application/json"}
            )
            
            # Parse the response
            verification_result = response.json()
            
            # Check if we need to retry with sandbox
            status = verification_result.get("status", 0)
            if status == 21007 and not sandbox_mode:
                # Receipt is from sandbox but was sent to production
                logger.info("Receipt is from sandbox, retrying with sandbox URL")
                return self.verify_receipt(receipt_data, sandbox_mode=True)
                
            # Return the verification result
            return verification_result
            
        except Exception as e:
            logger.error(f"Error verifying Apple receipt: {str(e)}")
            return {"status": -1, "error": str(e)}
            
    def parse_verification_result(self, verification_result):
        """
        Parse and extract useful information from the verification result
        
        Args:
            verification_result (dict): The verification result from Apple
            
        Returns:
            dict: Extracted info including product IDs, expiration dates, etc.
        """
        try:
            status = verification_result.get("status", -1)
            
            # If status is not 0, verification failed
            if status != 0:
                return {
                    "valid": False,
                    "status": status,
                    "error": f"Receipt verification failed with status {status}"
                }
                
            receipt = verification_result.get("receipt", {})
            latest_receipt_info = verification_result.get("latest_receipt_info", [])
            
            # If it's a list with elements, use the first one (most recent)
            # If it's not a list, convert to dict
            if isinstance(latest_receipt_info, list) and latest_receipt_info:
                latest_info = latest_receipt_info[0]
            elif not isinstance(latest_receipt_info, list):
                latest_info = latest_receipt_info
            else:
                latest_info = {}
                
            # Extract relevant information
            bundle_id = receipt.get("bundle_id")
            product_id = latest_info.get("product_id") or receipt.get("product_id")
            original_purchase_date = latest_info.get("original_purchase_date_ms")
            expires_date = latest_info.get("expires_date_ms")
            
            # Convert timestamps to dates if available
            if original_purchase_date:
                original_purchase_date = datetime.fromtimestamp(int(original_purchase_date) / 1000)
            
            if expires_date:
                expires_date = datetime.fromtimestamp(int(expires_date) / 1000)
                
            # Check if subscription is still valid
            subscription_active = False
            if expires_date:
                subscription_active = expires_date > datetime.now()
                
            return {
                "valid": True,
                "subscription_active": subscription_active,
                "bundle_id": bundle_id,
                "product_id": product_id,
                "original_purchase_date": original_purchase_date,
                "expires_date": expires_date,
                "transaction_id": latest_info.get("transaction_id"),
                "original_transaction_id": latest_info.get("original_transaction_id")
            }
            
        except Exception as e:
            logger.error(f"Error parsing Apple verification result: {str(e)}")
            return {"valid": False, "error": str(e)}
