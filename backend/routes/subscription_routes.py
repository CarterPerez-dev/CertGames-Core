@subscription_bp.route('/verify-session', methods=['POST'])
def verify_session():
    """
    Simplified verify-session endpoint to fix the stuck verification issue
    """
    data = request.json
    session_id = data.get('sessionId')
    
    # Enhanced logging
    current_app.logger.info(f"Verify session request received for: {session_id}")
    
    if not session_id:
        current_app.logger.error("No session ID provided")
        return jsonify({"success": False, "error": "Session ID required"}), 400
    
    try:
        # Check if this session was already verified
        existing = db.verified_sessions.find_one({"session_id": session_id})
        if existing:
            user_id = existing.get("user_id")
            current_app.logger.info(f"Session already verified, returning user: {user_id}")
            return jsonify({
                "success": True,
                "userId": user_id,
                "needsUsername": existing.get("needs_username", False)
            })
        
        # Retrieve the Stripe session
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            current_app.logger.info(f"Retrieved session from Stripe: {session_id}, status: {session.payment_status}")
        except stripe.error.StripeError as e:
            current_app.logger.error(f"Stripe error retrieving session: {str(e)}")
            return jsonify({"success": False, "error": f"Stripe error: {str(e)}"}), 500
        
        # Check payment status
        if session.payment_status != 'paid':
            current_app.logger.error(f"Payment not completed. Status: {session.payment_status}")
            return jsonify({
                "success": False, 
                "error": f"Payment not completed. Status: {session.payment_status}"
            }), 400
            
        # Extract session data
        customer_id = session.get('customer')
        user_id = session.get('client_reference_id')
        metadata = session.get('metadata', {})
        subscription_id = session.get('subscription')
        
        current_app.logger.info(f"Session data: customer_id={customer_id}, user_id={user_id}, metadata={metadata}")
        
        # If it's an existing user (client_reference_id is set)
        if user_id:
            try:
                # Update subscription info
                mainusers_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        "subscriptionActive": True,
                        "stripeCustomerId": customer_id,
                        "stripeSubscriptionId": subscription_id,
                        "subscriptionStatus": "active",
                        "subscriptionPlatform": "web"
                    }}
                )
                
                # Record successful verification
                db.verified_sessions.insert_one({
                    "session_id": session_id,
                    "user_id": user_id,
                    "needs_username": False,
                    "created_at": datetime.utcnow()
                })
                
                return jsonify({
                    "success": True,
                    "userId": user_id,
                    "needsUsername": False
                })
            except Exception as e:
                current_app.logger.error(f"Error updating existing user: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        # For new users - process registration data from metadata
        elif metadata and 'pendingRegistration' in metadata:
            try:
                # Parse registration data
                reg_data = json.loads(metadata['pendingRegistration'])
                reg_type = reg_data.get('registrationType', 'standard')
                
                current_app.logger.info(f"Registration type: {reg_type}, data: {reg_data}")
                
                # Process based on registration type
                if reg_type == 'standard':
                    # Get standard registration data
                    email = reg_data.get('email')
                    username = reg_data.get('username')
                    password = reg_data.get('password')  # May be None
                    
                    if not email or not username:
                        return jsonify({"success": False, "error": "Missing email or username"}), 400
                    
                    # Check if user already exists
                    existing_user = mainusers_collection.find_one({
                        "$or": [
                            {"username": username},
                            {"email": email}
                        ]
                    })
                    
                    if existing_user:
                        # Update existing user
                        user_id = str(existing_user["_id"])
                        mainusers_collection.update_one(
                            {"_id": existing_user["_id"]},
                            {"$set": {
                                "subscriptionActive": True,
                                "stripeCustomerId": customer_id,
                                "stripeSubscriptionId": subscription_id,
                                "subscriptionStatus": "active",
                                "subscriptionPlatform": "web"
                            }}
                        )
                    else:
                        # Create new user
                        user_data = {
                            'username': username,
                            'email': email,
                            'subscriptionActive': True,
                            'stripeCustomerId': customer_id,
                            'stripeSubscriptionId': subscription_id,
                            'subscriptionStatus': 'active',
                            'subscriptionPlatform': 'web',
                            'coins': 0,
                            'xp': 0,
                            'level': 1,
                            'achievements': []
                        }
                        
                        # Add password if available
                        if password:
                            user_data['password'] = hash_password(password)
                        else:
                            # Try to find password in temp registrations
                            temp_reg = db.temp_registrations.find_one({
                                "username": username,
                                "email": email
                            })
                            
                            if temp_reg and 'password' in temp_reg:
                                user_data['password'] = temp_reg['password']
                        
                        # Create user
                        result = create_user(user_data)
                        user_id = str(result)
                        current_app.logger.info(f"Created new standard user: {user_id}")
                    
                    # Record verification
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": user_id,
                        "needs_username": False,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": user_id,
                        "needsUsername": False
                    })
                    
                elif reg_type == 'oauth':
                    # Handle OAuth registration
                    provider = reg_data.get('provider')
                    needs_username = reg_data.get('needsUsername', True)
                    
                    # Generate temp email if not provided
                    email = reg_data.get('email', f"temp_{int(time.time())}@example.com")
                    
                    # Create minimal user record
                    user_data = {
                        'email': email,
                        'username': f"user_{int(time.time())}",  # Temporary username
                        'oauth_provider': provider.lower() if provider else None,
                        'subscriptionActive': True,
                        'stripeCustomerId': customer_id,
                        'stripeSubscriptionId': subscription_id,
                        'subscriptionStatus': 'active',
                        'subscriptionPlatform': 'web',
                        'coins': 0,
                        'xp': 0,
                        'level': 1,
                        'achievements': [],
                        'needs_username': True
                    }
                    
                    # Create user
                    result = create_user(user_data)
                    user_id = str(result)
                    current_app.logger.info(f"Created new OAuth user: {user_id}")
                    
                    # Record verification
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": user_id,
                        "needs_username": needs_username,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": user_id,
                        "needsUsername": needs_username
                    })
                    
                elif reg_type == 'renewal':
                    # Process subscription renewal
                    renewal_user_id = reg_data.get('userId')
                    
                    if not renewal_user_id:
                        return jsonify({
                            "success": False,
                            "error": "No user ID provided for renewal"
                        }), 400
                    
                    # Update subscription
                    mainusers_collection.update_one(
                        {"_id": ObjectId(renewal_user_id)},
                        {"$set": {
                            "subscriptionActive": True,
                            "stripeCustomerId": customer_id,
                            "stripeSubscriptionId": subscription_id,
                            "subscriptionStatus": "active", 
                            "subscriptionPlatform": "web"
                        }}
                    )
                    
                    # Record verification
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": renewal_user_id,
                        "needs_username": False,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": renewal_user_id,
                        "needsUsername": False
                    })
                    
                else:
                    return jsonify({
                        "success": False,
                        "error": f"Unknown registration type: {reg_type}"
                    }), 400
                    
            except json.JSONDecodeError:
                current_app.logger.error("Failed to parse pendingRegistration JSON")
                return jsonify({
                    "success": False,
                    "error": "Invalid registration data format"
                }), 400
            except Exception as e:
                current_app.logger.error(f"Error processing registration: {str(e)}")
                traceback.print_exc()
                return jsonify({
                    "success": False,
                    "error": f"Registration error: {str(e)}"
                }), 500
                
        else:
            # No user ID or registration data found
            current_app.logger.error("No user ID or registration data in session")
            
            # FALLBACK: Create a minimal user account just to continue
            try:
                # Use customer email from session if available
                email = session.customer_details.email if hasattr(session, 'customer_details') and hasattr(session.customer_details, 'email') else f"user_{int(time.time())}@example.com"
                
                user_data = {
                    'username': f"user_{int(time.time())}",
                    'email': email,
                    'subscriptionActive': True,
                    'stripeCustomerId': customer_id,
                    'stripeSubscriptionId': subscription_id,
                    'subscriptionStatus': 'active',
                    'subscriptionPlatform': 'web',
                    'coins': 0,
                    'xp': 0,
                    'level': 1,
                    'achievements': [],
                    'needs_username': True
                }
                
                result = create_user(user_data)
                user_id = str(result)
                current_app.logger.info(f"Created fallback user: {user_id}")
                
                # Record verification
                db.verified_sessions.insert_one({
                    "session_id": session_id,
                    "user_id": user_id,
                    "needs_username": True,
                    "created_at": datetime.utcnow()
                })
                
                return jsonify({
                    "success": True,
                    "userId": user_id,
                    "needsUsername": True,
                    "message": "Fallback user created"
                })
            except Exception as e:
                current_app.logger.error(f"Fallback user creation failed: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": f"Could not create fallback user: {str(e)}"
                }), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected verification error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500
