# backend/utils/deployment_service.py
import os
import json
import logging
import requests
import base64
import time
from flask import current_app
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DeploymentService:
    """Service for deploying portfolios to GitHub and Vercel"""
    
    def __init__(self):
        self.github_api_url = "https://api.github.com"
        self.vercel_api_url = "https://api.vercel.com"
    
    async def deploy_to_vercel(self, user_id, portfolio_id, github_token, vercel_token, portfolio_components):
        """
        Deploy a portfolio to Vercel via GitHub
        
        Args:
            user_id (str): User ID
            portfolio_id (str): Portfolio ID
            github_token (str): GitHub personal access token
            vercel_token (str): Vercel API token
            portfolio_components (dict): Portfolio components
            
        Returns:
            dict: Deployment information including URL
        """
        try:
            logger.info(f"Starting deployment process for portfolio {portfolio_id}")
            
            # 1. Create GitHub repository
            repo_name = f"portfolio-{user_id}-{portfolio_id[:6]}"
            repo_info = await self._create_github_repo(github_token, repo_name)
            repo_url = repo_info['html_url']
            
            # 2. Upload files to GitHub
            await self._upload_files_to_github(github_token, repo_info['full_name'], portfolio_components)
            
            # 3. Create Vercel project
            vercel_project = await self._create_vercel_project(vercel_token, repo_url, repo_name)
            
            # 4. Deploy to Vercel
            deployment = await self._trigger_vercel_deployment(vercel_token, vercel_project['id'])
            
            # 5. Wait for deployment to complete
            deployment_url = await self._wait_for_vercel_deployment(vercel_token, deployment['id'])
            
            return {
                "success": True,
                "deployment_url": deployment_url,
                "github_repo": repo_url,
                "vercel_project_id": vercel_project['id']
            }
            
        except Exception as e:
            logger.exception(f"Deployment failed: {str(e)}")
            
            # Check for common errors and provide better messages
            error_str = str(e)
            if "name already exists" in error_str:
                error_msg = "Repository already exists. This may be from a previous deployment attempt."
            elif "rate limit" in error_str.lower():
                error_msg = "GitHub API rate limit exceeded. Please try again in a few minutes."
            else:
                error_msg = f"Deployment failed: {str(e)}"
            
            raise Exception(error_msg)
    
    def deploy_to_vercel_sync(self, user_id, portfolio_id, github_token, vercel_token, portfolio_components):
        """
        Synchronous wrapper for the async deploy_to_vercel function
        """
        import asyncio
        
        # Create a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run the async function in the event loop
            result = loop.run_until_complete(
                self.deploy_to_vercel(user_id, portfolio_id, github_token, vercel_token, portfolio_components)
            )
            return result
        finally:
            # Clean up
            loop.close()    
    
    
    async def _create_github_repo(self, github_token, repo_name):
        """Create a new GitHub repository or use existing one"""
        logger.info(f"Checking for existing GitHub repository: {repo_name}")
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # First check if the repo exists
        existing_repo_response = requests.get(
            f"{self.github_api_url}/repos/{repo_name}", 
            headers=headers
        )
        
        # If it exists, use it
        if existing_repo_response.status_code == 200:
            logger.info(f"Repository {repo_name} already exists, using it")
            repo_data = existing_repo_response.json()
            return {
                "name": repo_data["name"],
                "full_name": repo_data["full_name"],
                "html_url": repo_data["html_url"]
            }
        
        # If it doesn't exist, create it
        payload = {
            "name": repo_name,
            "description": "Portfolio website created with Portfolio Generator",
            "private": False,
            "auto_init": True
        }
        
        # Try to create repo
        response = requests.post(
            f"{self.github_api_url}/user/repos", 
            headers=headers, 
            json=payload
        )
        
        # Handle "name already exists" error (status 422)
        if response.status_code == 422 and "name already exists" in response.text:
            # Add a timestamp to make the name unique
            timestamp = int(time.time())
            new_repo_name = f"{repo_name}-{timestamp}"
            logger.info(f"Repository name already exists, trying with new name: {new_repo_name}")
            
            # Update payload with new name
            payload["name"] = new_repo_name
            
            # Try again with the new name
            response = requests.post(
                f"{self.github_api_url}/user/repos", 
                headers=headers, 
                json=payload
            )
        
        if response.status_code != 201:
            logger.error(f"GitHub repo creation failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to create GitHub repository: {response.text}")
        
        return response.json()
    
    async def _upload_files_to_github(self, github_token, repo_full_name, portfolio_components):
        """Upload all portfolio files to GitHub"""
        logger.info(f"Uploading files to GitHub repository: {repo_full_name}")
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Create package.json if not present
        if "package.json" not in portfolio_components:
            portfolio_components["package.json"] = self._generate_package_json()
        
        # Add vercel.json configuration
        portfolio_components["vercel.json"] = self._generate_vercel_config()
        
        # Upload each file
        for file_path, content in portfolio_components.items():
            encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            
            payload = {
                "message": f"Add {file_path}",
                "content": encoded_content
            }
            
            response = requests.put(
                f"{self.github_api_url}/repos/{repo_full_name}/contents/{file_path}", 
                headers=headers, 
                json=payload
            )
            
            if response.status_code not in [201, 200]:
                logger.error(f"Failed to upload {file_path}: {response.status_code} - {response.text}")
                raise Exception(f"Failed to upload file {file_path}")
    
    async def _create_vercel_project(self, vercel_token, github_url, project_name):
        """Create a new Vercel project linked to GitHub repo"""
        logger.info(f"Creating Vercel project for repository: {github_url}")
        
        headers = {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "name": project_name,
            "gitRepository": {
                "type": "github",
                "repo": github_url.replace("https://github.com/", "")
            }
        }
        
        response = requests.post(
            f"{self.vercel_api_url}/v9/projects", 
            headers=headers, 
            json=payload
        )
        
        if response.status_code != 201:
            logger.error(f"Vercel project creation failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to create Vercel project: {response.text}")
        
        return response.json()
    
    async def _trigger_vercel_deployment(self, vercel_token, project_id):
        """Trigger a deployment on Vercel"""
        logger.info(f"Triggering Vercel deployment for project: {project_id}")
        
        headers = {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "target": "production"
        }
        
        response = requests.post(
            f"{self.vercel_api_url}/v13/deployments?projectId={project_id}", 
            headers=headers, 
            json=payload
        )
        
        if response.status_code != 200:
            logger.error(f"Vercel deployment triggering failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to trigger Vercel deployment: {response.text}")
        
        return response.json()
    
    async def _wait_for_vercel_deployment(self, vercel_token, deployment_id, timeout=300):
        """Wait for Vercel deployment to complete"""
        logger.info(f"Waiting for Vercel deployment {deployment_id} to complete")
        
        headers = {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json"
        }
        
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            response = requests.get(
                f"{self.vercel_api_url}/v13/deployments/{deployment_id}", 
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to check deployment status: {response.status_code} - {response.text}")
                raise Exception(f"Failed to check deployment status: {response.text}")
            
            deployment = response.json()
            state = deployment.get('state', '')
            
            if state == 'READY':
                # Get the deployment URL
                return deployment.get('url', f"https://{deployment.get('name')}.vercel.app")
            elif state == 'ERROR':
                raise Exception(f"Deployment failed with error: {deployment.get('errorMessage', 'Unknown error')}")
            
            # Wait before checking again
            time.sleep(5)
        
        raise Exception(f"Deployment timed out after {timeout} seconds")
    
    def _generate_package_json(self):
        """Generate a basic package.json file"""
        return json.dumps({
            "name": "portfolio",
            "version": "0.1.0",
            "private": True,
            "dependencies": {
                "react": "^18.2.0",
                "react-dom": "^18.2.0",
                "react-router-dom": "^6.10.0",
                "react-scripts": "5.0.1"
            },
            "scripts": {
                "start": "react-scripts start",
                "build": "react-scripts build",
                "test": "react-scripts test",
                "eject": "react-scripts eject"
            },
            "eslintConfig": {
                "extends": ["react-app"]
            },
            "browserslist": {
                "production": [">0.2%", "not dead", "not op_mini all"],
                "development": ["last 1 chrome version", "last 1 firefox version", "last 1 safari version"]
            }
        }, indent=2)
    
    def _generate_vercel_config(self):
        """Generate vercel.json configuration"""
        return json.dumps({
            "version": 2,
            "builds": [{ "src": "package.json", "use": "@vercel/static-build" }],
            "routes": [{ "src": "/(.*)", "dest": "/index.html" }]
        }, indent=2)

# Initialize the service
deployment_service = DeploymentService()
