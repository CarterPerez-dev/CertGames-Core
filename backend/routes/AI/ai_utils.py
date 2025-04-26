def get_current_user_id():
    """Extract user ID from all possible sources"""
    user_id = None
    
    # Check session
    if 'userId' in session:
        user_id = session.get('userId')
    
    # Check JWT
    if user_id is None and current_app.config.get('JWT_SECRET_KEY'):
        try:
            verify_jwt_in_request(optional=True)
            jwt_identity = get_jwt_identity()
            if jwt_identity:
                user_id = jwt_identity
        except Exception:
            pass
    
    # Check headers
    if user_id is None:
        user_id = request.headers.get('X-User-Id')
    
    # Check request body
    if user_id is None:
        try:
            data = request.get_json(silent=True) or {}
            user_id = data.get('userId')
        except Exception:
            pass
    
    return user_id
