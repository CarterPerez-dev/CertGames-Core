# backend/helpers/gemini_helper.py
import os
import json
import logging
import time
import random
import requests
from flask import current_app
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class GeminiHelper:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("GEMINI_API_KEY not found in environment variables")
            raise ValueError("GEMINI_API_KEY not found. Please set it in your environment variables.")
        
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.model = "gemini-2.5-pro-preview-05-06"
        self.max_retries = 3
        self.backoff_factor = 2  # Exponential backoff
        
        logger.info(f"GeminiHelper initialized with model: {self.model}")
    
    def generate_portfolio(self, resume_text, preferences, max_tokens=20000, temperature=0.2):
        """
        Generate a complete portfolio website based on resume text and user preferences.
        
        Args:
            resume_text (str): The user's resume in text format
            preferences (dict): User preferences for portfolio styling and features
            max_tokens (int): Maximum tokens for generation
            temperature (float): Temperature for generation (lower means more deterministic)
            
        Returns:
            dict: Portfolio components including HTML, CSS, and JavaScript code
        """
        logger.info("Starting portfolio generation with Gemini API")
        
        # Construct prompt
        prompt = self._construct_portfolio_prompt(resume_text, preferences)
        
        # Call Gemini API with retry logic
        for attempt in range(self.max_retries):
            try:
                response = self._call_gemini_api(prompt, max_tokens, temperature)
                
                # Parse the response into portfolio components
                portfolio = self._parse_portfolio_response(response)
                
                logger.info("Successfully generated portfolio components")
                return portfolio
                
            except Exception as e:
                wait_time = self.backoff_factor ** attempt + random.uniform(0, 1)
                logger.warning(f"Attempt {attempt+1}/{self.max_retries} failed: {str(e)}. Retrying in {wait_time:.2f} seconds.")
                time.sleep(wait_time)
                
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to generate portfolio after {self.max_retries} attempts")
                    raise
        
        # Should never reach here due to exception in the loop
        return None
    
    def fix_portfolio_error(self, error_message, component_code, resume_text, preferences):
        """
        Fix errors in generated portfolio code
        
        Args:
            error_message (str): Error message from compilation/execution
            component_code (str): The component code that has errors
            resume_text (str): Original resume text
            preferences (dict): Original user preferences
            
        Returns:
            str: Fixed component code
        """
        prompt = self._construct_fix_error_prompt(error_message, component_code, resume_text, preferences)
        
        try:
            response = self._call_gemini_api(prompt, max_tokens=8000, temperature=0.1)
            fixed_code = self._extract_code_from_response(response)
            return fixed_code
        except Exception as e:
            logger.error(f"Error fixing portfolio code: {str(e)}")
            raise
    
    def _call_gemini_api(self, prompt, max_tokens=20000, temperature=0.2):
        """Call the Gemini API with given parameters"""
        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
        
        # Configure safety settings to be permissive
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
        ]
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
                "topP": 0.95,
                "topK": 40
            },
            "safetySettings": safety_settings
        }
        
        logger.debug(f"Calling Gemini API with prompt length: {len(prompt)}")
        
        response = requests.post(url, json=payload)
        
        if response.status_code != 200:
            logger.error(f"Gemini API error: {response.status_code} - {response.text}")
            raise Exception(f"API Error: {response.status_code} - {response.text}")
        
        return response.json()
    
    def _construct_portfolio_prompt(self, resume_text, preferences):
        """Construct a detailed prompt for portfolio generation"""
        template_style = preferences.get('template_style', 'modern')
        color_scheme = preferences.get('color_scheme', 'professional')
        features = preferences.get('features', [])
        
        feature_requests = "\n".join([f"- {feature}" for feature in features])
        
        prompt = f"""
        As an expert web developer, create a professional portfolio website for a job seeker based on their resume. 
        I need you to generate a complete React-based portfolio that showcases their skills and experience effectively.
        
        RESUME TEXT:
        {resume_text}
        
        STYLE PREFERENCES:
        - Template style: {template_style}
        - Color scheme: {color_scheme}
        - Requested features: 
        {feature_requests}
        
        TECHNICAL REQUIREMENTS:
        1. Create a clean, responsive React-based portfolio website
        2. Use modern React with functional components and hooks
        3. Create these key files:
           - src/App.js - Main application component
           - src/index.js - Entry point
           - src/index.css - Global styles
           - public/index.html - HTML template
           - package.json - Dependencies
           - Component files for each section (About, Projects, Skills, Contact, etc.)
           
        4. Make it visually appealing with clean CSS (no frameworks required, but can use simple CSS)
        5. Ensure the code is production-ready, well-structured, and error-free
        6. Include comments to explain the code structure
        7. Keep the design clean, professional and fully responsive
        
        DEPLOYMENT REQUIREMENTS:
        The code will be deployed to Vercel, so ensure it's compatible with their platform.
        
        FORMAT YOUR RESPONSE AS FOLLOWS:
        
        ```analysis
        # Resume Analysis 
        [Brief analysis of the key skills, experience, and projects from the resume]
        
        # Portfolio Structure
        [Explanation of the overall structure and components]
        ```
        
        ```package.json
        [Complete package.json file with all necessary dependencies]
        ```
        
        ```html:public/index.html
        [Complete HTML file]
        ```
        
        ```javascript:src/index.js
        [Complete index.js file]
        ```
        
        ```css:src/index.css
        [Complete index.css file with global styles]
        ```
        
        ```javascript:src/App.js
        [Complete App.js file]
        ```
        
        FOR EACH COMPONENT FILE:
        
        ```javascript:src/components/ComponentName.js
        [Component code]
        ```
        
        ```css:src/components/ComponentName.css
        [Component styling]
        ```
        
        DO NOT OMIT ANY IMPORTANT FILES. Include all necessary files to create a complete, functioning portfolio website.
        """
        
        return prompt
    
    def _construct_fix_error_prompt(self, error_message, component_code, resume_text, preferences):
        """Construct a prompt to fix errors in generated code"""
        prompt = f"""
        I need help fixing errors in a generated React portfolio component. 
        
        ERROR MESSAGE:
        {error_message}
        
        COMPONENT CODE WITH ERRORS:
        ```
        {component_code}
        ```
        
        CONTEXT FROM RESUME:
        {resume_text[:500]}... [truncated]
        
        FIX INSTRUCTIONS:
        1. Carefully analyze the error message
        2. Fix all issues in the component code
        3. Ensure the component still matches the resume information
        4. Return ONLY the corrected code without explanations
        
        FIXED CODE:
        ```
        """
        return prompt
    
    def _parse_portfolio_response(self, response):
        """Parse the Gemini API response into portfolio components"""
        try:
            # Extract the generated text from the response
            generated_text = ""
            candidates = response.get('candidates', [])
            if candidates and 'content' in candidates[0]:
                content = candidates[0]['content']
                if 'parts' in content:
                    for part in content['parts']:
                        if 'text' in part:
                            generated_text += part['text']
            
            if not generated_text:
                logger.error("No generated text found in API response")
                raise ValueError("Empty response from Gemini API")
            
            # Parse the code blocks from the generated text
            portfolio_components = self._extract_components_from_text(generated_text)
            
            if not portfolio_components:
                logger.error("Failed to extract components from generated text")
                raise ValueError("Could not parse portfolio components from API response")
            
            return portfolio_components
            
        except Exception as e:
            logger.error(f"Error parsing portfolio response: {str(e)}")
            raise
    
    def _extract_components_from_text(self, text):
        """Extract code components from the generated text using regex"""
        import re
        
        # Define patterns for different code blocks
        patterns = {
            'analysis': r'```analysis\s*([\s\S]*?)```',
            'package.json': r'```(?:package\.json|json:package\.json)\s*([\s\S]*?)```',
            'public/index.html': r'```(?:html:public/index\.html|public/index\.html)\s*([\s\S]*?)```',
            'src/index.js': r'```(?:javascript:src/index\.js|src/index\.js)\s*([\s\S]*?)```',
            'src/index.css': r'```(?:css:src/index\.css|src/index\.css)\s*([\s\S]*?)```',
            'src/App.js': r'```(?:javascript:src/App\.js|src/App\.js)\s*([\s\S]*?)```',
        }
        
        # Pattern for component files
        component_pattern = r'```(?:javascript|js):src/components/(\w+)\.js\s*([\s\S]*?)```'
        component_css_pattern = r'```(?:css):src/components/(\w+)\.css\s*([\s\S]*?)```'
        
        # Extract components
        components = {}
        
        # Extract main files
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                components[key] = match.group(1).strip()
        
        # Extract component files
        component_matches = re.findall(component_pattern, text)
        for name, code in component_matches:
            components[f'src/components/{name}.js'] = code.strip()
        
        # Extract component CSS files
        component_css_matches = re.findall(component_css_pattern, text)
        for name, code in component_css_matches:
            components[f'src/components/{name}.css'] = code.strip()
        
        return components
    
    def _extract_code_from_response(self, response):
        """Extract fixed code from error-fixing response"""
        generated_text = ""
        candidates = response.get('candidates', [])
        if candidates and 'content' in candidates[0]:
            content = candidates[0]['content']
            if 'parts' in content:
                for part in content['parts']:
                    if 'text' in part:
                        generated_text += part['text']
        
        # Extract code block
        import re
        code_match = re.search(r'```(?:javascript|js)?\s*([\s\S]*?)```', generated_text)
        if code_match:
            return code_match.group(1).strip()
        
        return generated_text.strip()

# Initialize the helper
gemini_helper = GeminiHelper()
