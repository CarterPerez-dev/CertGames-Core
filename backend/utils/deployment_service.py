import os
import json
import logging
import requests
import base64
import time

logger = logging.getLogger(__name__)

class DeploymentService:
    def __init__(self):
        self.github_api_url = "https://api.github.com"
        self.vercel_api_url = "https://api.vercel.com"

    def deploy_to_vercel(self, user_id, portfolio_id, github_token, vercel_token, portfolio_components):
        """
        Deploy a portfolio to Vercel via GitHub (Synchronous Version)
        """
        try:
  
            portfolio_id_str = str(portfolio_id)
            repo_name_base = f"portfolio-{user_id}-{portfolio_id_str[:6]}"
            repo_info = self._create_github_repo(github_token, repo_name_base)
            
            github_html_url = repo_info['html_url']
            github_full_name = repo_info['full_name'] 
            actual_repo_name_on_github = repo_info['name'] 
            
            logger.info(f"GitHub repository created/retrieved: {github_full_name}, URL: {github_html_url}")

            # 2. Upload files to GitHub
            self._upload_files_to_github(github_token, github_full_name, portfolio_components)
            logger.info(f"Files uploaded to GitHub repository: {github_full_name}")
            
            # 3. Create Vercel project linked to the GitHub repository.
            vercel_project = self._create_vercel_project(vercel_token, github_full_name, actual_repo_name_on_github)
            
            vercel_project_id = vercel_project.get('id')
            if not vercel_project_id:
                logger.error(f"Vercel project creation response missing 'id': {json.dumps(vercel_project)}")
                raise Exception("Failed to get project ID from Vercel project creation response.")
            
            logger.info(f"Vercel project created: {vercel_project_id}, Name: {vercel_project.get('name')}")

            link_info = vercel_project.get('link')
            if not link_info or 'repoId' not in link_info:
                logger.error(f"Vercel project response missing link.repoId: {json.dumps(vercel_project)}")
                raise Exception("Failed to get GitHub repoId from Vercel project 'link' details.")
            
            github_repo_id_for_vercel = link_info['repoId']
            logger.info(f"GitHub Repo ID for Vercel deployment: {github_repo_id_for_vercel}")
                       
            # 4. Trigger deployment on Vercel
            deployment_info = self._trigger_vercel_deployment(vercel_token, vercel_project_id, github_repo_id_for_vercel)
            
            vercel_deployment_uid = deployment_info.get('uid') or deployment_info.get('id')
            if not vercel_deployment_uid:
                logger.error(f"Vercel deployment trigger response missing 'uid' or 'id': {json.dumps(deployment_info)}")
                raise Exception("Failed to get deployment UID from Vercel trigger response.")
            logger.info(f"Vercel deployment triggered, UID: {vercel_deployment_uid}")

            # 5. Wait for deployment to complete
            deployment_url = self._wait_for_vercel_deployment(vercel_token, vercel_deployment_uid)
            logger.info(f"Vercel deployment completed. URL: {deployment_url}")
            
            return {
                "success": True,
                "deployment_url": deployment_url,
                "github_repo": github_html_url,
                "vercel_project_id": vercel_project_id
            }
            
        except Exception as e:
            logger.exception(f"Deployment failed: {str(e)}")
            error_str = str(e)
            if "name already exists" in error_str and "github" in error_str.lower() :
                error_msg = "A GitHub repository with a similar name already exists. This might be from a previous attempt."
            elif "rate limit" in error_str.lower():
                error_msg = "API rate limit exceeded (GitHub or Vercel). Please try again in a few minutes."
            elif "Failed to trigger Vercel deployment" in error_str:
                actual_vercel_error = error_str.split("Failed to trigger Vercel deployment:", 1)[-1].strip()
                error_msg = f"Vercel deployment trigger failed: {actual_vercel_error}"
            else:
                error_msg = f"Deployment process failed: {str(e)}"
            raise Exception(error_msg)

    def _create_github_repo(self, github_token, repo_name):
        logger.info(f"Attempting to create GitHub repository: {repo_name}")
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "name": repo_name,
            "description": "Portfolio website created with Portfolio Generator",
            "private": False,
            "auto_init": True # Creates a README, .gitignore, and default branch (main)
        }
        
        response = requests.post(
            f"{self.github_api_url}/user/repos", 
            headers=headers, 
            json=payload
        )
        
        if response.status_code == 422 and "name already exists" in response.text.lower():
            timestamp = int(time.time())
            new_repo_name = f"{repo_name}-{timestamp}"
            logger.info(f"GitHub repository name '{repo_name}' already exists. Trying with new name: {new_repo_name}")
            payload["name"] = new_repo_name
            response = requests.post(
                f"{self.github_api_url}/user/repos", 
                headers=headers, 
                json=payload
            )

        if response.status_code != 201: # 201 Created
            logger.error(f"GitHub repo creation failed: {response.status_code} - {response.text}")
            logger.error(f"Request payload: {json.dumps(payload)}")
            raise Exception(f"Failed to create GitHub repository: {response.text}")
        
        repo_data = response.json()
        logger.info(f"GitHub repository '{repo_data['full_name']}' created successfully.")
        return {
            "name": repo_data["name"],
            "full_name": repo_data["full_name"],
            "html_url": repo_data["html_url"]
        }

    def _upload_files_to_github(self, github_token, repo_full_name, portfolio_components):
        logger.info(f"Uploading files to GitHub repository: {repo_full_name}")
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        if "package.json" not in portfolio_components:
            portfolio_components["package.json"] = self._generate_package_json()
        portfolio_components["vercel.json"] = self._generate_vercel_config()
        
        for file_path, content_str in portfolio_components.items():
            if not isinstance(content_str, str):
                logger.error(f"Content for {file_path} is not a string: {type(content_str)}. Skipping upload.")
                continue

            encoded_content = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
            
            payload = {
                "message": f"Add {file_path}",
                "content": encoded_content,
                "branch": "main"
            }
            
            url = f"{self.github_api_url}/repos/{repo_full_name}/contents/{file_path}"
            response = requests.put(url, headers=headers, json=payload)
            
            if response.status_code not in [201, 200]: # 201 for create, 200 for update
                logger.error(f"Failed to upload {file_path} to GitHub: {response.status_code} - {response.text}")
                raise Exception(f"Failed to upload file {file_path} to GitHub: {response.text}")
            logger.debug(f"Successfully uploaded {file_path} to {repo_full_name}")

    def _create_vercel_project(self, vercel_token, github_repo_full_name, vercel_project_name):
        logger.info(f"Creating Vercel project '{vercel_project_name}' for GitHub repository: {github_repo_full_name}")
        headers = {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "name": vercel_project_name,
            "gitRepository": {
                "type": "github",
                "repo": github_repo_full_name
            },
            "framework": "create-react-app", 
        }
        
        response = requests.post(
            f"{self.vercel_api_url}/v9/projects", 
            headers=headers, 
            json=payload
        )
        
        if response.status_code not in [200, 201]:
            logger.error(f"Vercel project creation/linking failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to create or link Vercel project: {response.text}")
        
        logger.info(f"Vercel project creation/linking successful. Status: {response.status_code}")
        return response.json()
    
    def _trigger_vercel_deployment(self, vercel_token, vercel_project_id, github_repo_id_for_vercel):
        logger.info(f"Triggering Vercel deployment for project ID: {vercel_project_id} using GitHub repo ID: {github_repo_id_for_vercel}")
        headers = {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json"
        }
        deployment_name = f"portfolio-deployment-{int(time.time())}"
        payload = {
            "name": deployment_name,  
            "target": "production",
            "gitSource": {
                "type": "github",
                "repoId": github_repo_id_for_vercel,
                "ref": "main"
            }
        }
        
        url = f"{self.vercel_api_url}/v13/deployments?projectId={vercel_project_id}"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"Vercel deployment triggering failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to trigger Vercel deployment: {response.text}")
        
        logger.info("Vercel deployment triggered successfully.")
        return response.json()
    
    def _wait_for_vercel_deployment(self, vercel_token, deployment_uid, timeout=900):
        logger.info(f"Waiting for Vercel deployment {deployment_uid} to complete (timeout: {timeout}s)")
        headers = {"Authorization": f"Bearer {vercel_token}"}
        start_time = time.time()
        last_ready_state = "UNKNOWN"
    
        while (time.time() - start_time) < timeout:
            url = f"{self.vercel_api_url}/v13/deployments/{deployment_uid}"
            try:
                response = requests.get(url, headers=headers, timeout=60)
            except requests.exceptions.Timeout:
                logger.warning(f"Request to Vercel for deployment status {deployment_uid} timed out. Retrying...")
                time.sleep(5) 
                continue
            except requests.exceptions.RequestException as req_err:
                logger.error(f"Request error checking Vercel status for {deployment_uid}: {req_err}. Retrying...")
                time.sleep(5)
                continue
    
            if response.status_code != 200:
                logger.error(f"Failed to check Vercel deployment status for {deployment_uid}: {response.status_code} - {response.text}. Retrying...")
                time.sleep(5) 
                continue 
            
            try:
                deployment_data = response.json()
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON from Vercel status response for {deployment_uid}: {response.text}. Retrying...")
                time.sleep(5)
                continue
                
            ready_state = deployment_data.get('readyState')
            last_ready_state = ready_state
            
            logger.debug(f"Deployment {deployment_uid} readyState: {ready_state}. Details: {json.dumps(deployment_data)[:200]}...")
    
            if ready_state == 'READY':
                deployed_url = deployment_data.get('url')
                if not deployed_url:
                    logger.error(f"Deployment {deployment_uid} is READY but 'url' field is missing: {json.dumps(deployment_data)}")
                    raise Exception(f"Deployment {deployment_uid} is READY but 'url' field missing in Vercel response.")
                
                full_url = deployed_url if deployed_url.startswith("https://") or deployed_url.startswith("http://") else f"https://{deployed_url}"
                logger.info(f"Deployment {deployment_uid} is READY. URL: {full_url}")
                return full_url
            elif ready_state in ['ERROR', 'CANCELED']:
                error_details = deployment_data.get('error', {})
                error_message = error_details.get('message', 'Unknown Vercel deployment error.')
                
                # Try to get more detailed error information
                build_logs = None
                try:
                    # Look for build logs in the deployment data
                    if 'builds' in deployment_data and len(deployment_data['builds']) > 0:
                        build = deployment_data['builds'][0]
                        if 'error' in build:
                            build_logs = build.get('error')
                except Exception as e:
                    logger.error(f"Error extracting build logs: {str(e)}")
                    
                # Log everything we can find about the error
                logger.error(f"Vercel deployment {deployment_uid} failed. Error: {error_message}")
                if build_logs:
                    logger.error(f"Build logs: {build_logs}")
                
                raise Exception(f"Vercel deployment {ready_state}: {error_message} - Check build logs for details.")
            
            logger.info(f"Deployment {deployment_uid} current state: {ready_state}. Waiting...")
            time.sleep(10) 
        
        logger.error(f"Vercel deployment {deployment_uid} timed out after {timeout} seconds (last state: {last_ready_state}).")
        raise Exception(f"Vercel deployment timed out after {timeout} seconds (last state: {last_ready_state}).")

    def _generate_package_json(self):
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
                "extends": ["react-app", "react-app/jest"]
            },
            "browserslist": {
                "production": [">0.2%", "not dead", "not op_mini all"],
                "development": ["last 1 chrome version", "last 1 firefox version", "last 1 safari version"]
            }
        }, indent=2)

    def _generate_vercel_config(self):
        return json.dumps({
            "version": 2,
            "framework": "create-react-app",
            "builds": [
                { 
                    "src": "package.json", 
                    "use": "@vercel/static-build",
                    "config": { "outputDirectory": "build" }
                }
            ],
            "routes": [
                { "handle": "filesystem" },
                { "src": "/.*", "dest": "/index.html" }
            ]
        }, indent=2)


deployment_service = DeploymentService()
