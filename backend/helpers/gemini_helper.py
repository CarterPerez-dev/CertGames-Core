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
        self.max_retries = 2
        self.backoff_factor = 2  # Exponential backoff
        
        logger.info(f"GeminiHelper initialized with model: {self.model}")
    
    def generate_portfolio(self, resume_text, preferences, max_tokens=30000, temperature=0.1):
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
                
                # Log the raw response for debugging
                logger.debug(f"Raw Gemini API response length: {len(str(response))}")
                
                # Extract the generated text for logging (truncated)
                full_text = self._extract_text_from_response(response)
                logger.debug(f"Generated text preview (first 500 chars): {full_text[:500]}")
                
                # Parse the response into portfolio components
                portfolio = self._parse_portfolio_response(response)
                
                # Log successful component extraction
                component_count = len(portfolio) if portfolio else 0
                logger.info(f"Successfully generated {component_count} portfolio components")
                
                # Validate the required components are present
                self._validate_portfolio_components(portfolio)
                
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
    
    def _extract_text_from_response(self, response):
        """Extract full text from response for debugging purposes"""
        generated_text = ""
        candidates = response.get('candidates', [])
        if candidates and 'content' in candidates[0]:
            content = candidates[0]['content']
            if 'parts' in content:
                for part in content['parts']:
                    if 'text' in part:
                        generated_text += part['text']
        return generated_text
    
    def _validate_portfolio_components(self, components):
        """Validate that all required components are present"""
        required_components = [
            'public/index.html',
            'src/index.js', 
            'src/App.js', 
            'src/index.css',
            'src/reportWebVitals.js',
        ]
        
        missing = [comp for comp in required_components if comp not in components]
        if missing:
            logger.error(f"Missing required components: {missing}")
            raise ValueError(f"Generated portfolio is missing required components: {missing}")
        
        # Ensure we have at least one component file
        component_files = [k for k in components.keys() if k.startswith('src/components/')]
        if not component_files:
            logger.error("No component files found in generated portfolio")
            raise ValueError("Generated portfolio has no component files")
    
    def fix_portfolio_error(self, error_message, component_code, resume_text, preferences):
        """Fix errors in generated portfolio code"""
        try:
            prompt = self._construct_fix_error_prompt(error_message, component_code, resume_text, preferences)
            
            response = self._call_gemini_api(prompt, max_tokens=8000, temperature=0.1)
            fixed_code = self._extract_code_from_response(response)
            
            # Verify the response is not empty
            if not fixed_code or len(fixed_code) < 10:
                raise ValueError("Received empty or very short code from API")
                
            return fixed_code
        except Exception as e:
            logger.error(f"Error fixing code: {str(e)}")
            raise
    
    def _call_gemini_api(self, prompt, max_tokens=30000, temperature=0.1):
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
            # Check if response is HTML
            if response.text.strip().startswith('<!DOCTYPE') or response.text.strip().startswith('<html'):
                logger.error(f"Received HTML response from Gemini API instead of JSON. Status: {response.status_code}")
                logger.error(f"Response preview: {response.text[:200]}...")
                raise Exception(f"API returned HTML instead of JSON. Status: {response.status_code}. Please check API key validity and quotas.")
            else:
                logger.error(f"Gemini API error: {response.status_code} - {response.text}")
                raise Exception(f"API Error: {response.status_code} - {response.text}")
        
        try:
            return response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            logger.error(f"Response preview: {response.text[:200]}...")
            raise Exception(f"Invalid JSON response from API: {str(e)}")
    
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
           - - src/App.css - THIS FILE MUST BE COMPLETELY EMPTY WITH NO CODE WHATSOEVER
           - src/reportWebVitals.js - defualt reportWebVitals file, and the dependency added to package.json
           - public/index.html - HTML template
           - package.json - Dependencies
           - Component files for each section (About, Projects, Skills, Contact, etc.)
           
        4. Make it visually appealing with clean CSS (no frameworks required, but can use simple CSS)
        5. Ensure the code is production-ready, well-structured, and error-free
        6. Include comments to explain the code structure
        7. Keep the design clean, professional and fully responsive
        8. IMPORTANT Maximize {resume_text} utilization by creatively inventing impressive and relevant content to fill any informational gaps, strictly prohibiting all placeholder text
        
        DEPLOYMENT REQUIREMENTS:
        The code will be deployed to Vercel, so ensure it's compatible with their platform.
        
        FORMAT YOUR RESPONSE VERY CAREFULLY FOLLOWING THESE EXACT GUIDELINES:
        
        ```analysis
        # Resume Analysis 
        [Brief analysis of the key skills, experience, and projects from the resume]
        
        # Portfolio Structure
        [Explanation of the overall structure and components]
        ```
        
        ```package.json
        [Complete package.json file with all necessary dependencies including web-vitals]
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
        ```css:src/App.css
        [Complete App.css file EMPTY, RETURN AN EMPTY App.css with NO CODE]
        ```        
        
        ```javascript:src/reportWebVitals.js
        [Complete reportWebVitals.js file]
        ```        
        
        ```javascript:src/App.js
        [Complete App.js file]
        ```
        
        FOR EACH COMPONENT FILE, USE THIS EXACT FORMAT:
        
        ```javascript:src/components/ComponentName.js
        // Component code goes here
        ```
        
        ```css:src/components/ComponentName.css
        // Component styling goes here
        ```
        
        IMPORTANT FORMATTING RULES:
        1. DO NOT use prefixes like "javascript:" or "// src/components/ComponentName.js" inside the code blocks
        2. DO NOT create generic Component1.js, Component2.js files - use meaningful component names
        3. ALL component files should have clear, semantic names (e.g., About.js, Skills.js, etc.)
        4. DO NOT OMIT ANY IMPORTANT FILES
        5. Use the EXACT format for code blocks: ```language:filepath
        
        Include all necessary files to create a complete, functioning portfolio website.
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
            
            # Save raw response to a debug file for inspection
            try:
                debug_dir = os.path.join(os.getcwd(), 'debug_logs')
                os.makedirs(debug_dir, exist_ok=True)
                with open(os.path.join(debug_dir, f'gemini_response_{int(time.time())}.txt'), 'w') as f:
                    f.write(generated_text)
            except Exception as log_err:
                logger.warning(f"Could not save debug response: {log_err}")
            
            # Parse the code blocks from the generated text
            portfolio_components = self._extract_components_from_text(generated_text)
            
            if not portfolio_components:
                logger.error("Failed to extract components from generated text")
                raise ValueError("Could not parse portfolio components from API response")
            
            if "src/App.css" in portfolio_components:
                portfolio_components["src/App.css"] = ""
                logger.info("Ensuring App.css is empty as required")             
            
            
            return portfolio_components
            
        except Exception as e:
            logger.error(f"Error parsing portfolio response: {str(e)}")
            raise
    
    def _extract_components_from_text(self, text):
        """Extract code components from the generated text using regex"""
        import re
        
        # Define patterns for different code blocks - IMPROVED to be more flexible
        patterns = {
            'analysis': r'```(?:analysis)\s*([\s\S]*?)```',
            'package.json': r'```(?:package\.json|json:package\.json|json)\s*([\s\S]*?)```',
            'public/index.html': r'```(?:html:public/index\.html|public/index\.html|html)\s*([\s\S]*?)```',
            'src/index.js': r'```(?:javascript:src/index\.js|src/index\.js|js:src/index\.js|javascript)\s*([\s\S]*?)```',
            'src/index.css': r'```(?:css:src/index\.css|src/index\.css|css)\s*([\s\S]*?)```',
            'src/App.js': r'```(?:javascript:src/App\.js|src/App\.js|js:src/App\.js)\s*([\s\S]*?)```',
            'src/App.css': r'```(?:css:src/App\.css|src/App\.css|css)\s*([\s\S]*?)```',
            'src/reportWebVitals.js': r'```(?:javascript:src/reportWebVitals\.js|src/reportWebVitals\.js|js:src/reportWebVitals\.js)\s*([\s\S]*?)```',
        }
        
        # More flexible patterns for component files
        component_pattern = r'```(?:javascript|js)(?::)?src/components/([a-zA-Z0-9_-]+)\.js\s*([\s\S]*?)```'
 
        # Fallback pattern if the more specific one doesn't find matches
        component_fallback_pattern = r'```(?:javascript|js)\s*(?:\/\/|#)\s*src\/components\/([a-zA-Z0-9_-]+)\.js\s*([\s\S]*?)```'
        nested_component_pattern = r'```(?:javascript|js)(?::)?src/components/([a-zA-Z0-9_-]+)/\1\.js\s*([\s\S]*?)```'
        component_css_pattern = r'```(?:css):src/components/([a-zA-Z0-9_-]+)\.css\s*([\s\S]*?)```'
        # Fallback pattern for CSS
        component_css_fallback_pattern = r'```(?:css)\s*(?:\/\/|#)\s*src\/components\/([a-zA-Z0-9_-]+)\.css\s*([\s\S]*?)```'
        
        # Extract components
        components = {}
        
        # Extract main files
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                components[key] = match.group(1).strip()
                logger.debug(f"Extracted {key}")
            else:
                logger.warning(f"Failed to extract {key} using pattern {pattern}")
        
        # Extract component files
        component_matches = re.findall(component_pattern, text)
        if not component_matches:
            # Try nested component pattern
            logger.info("Trying nested component pattern")
            nested_matches = re.findall(nested_component_pattern, text)
            for name, code in nested_matches:
                components[f'src/components/{name}/{name}.js'] = code.strip()
                logger.debug(f"Extracted nested component src/components/{name}/{name}.js")
        
        for name, code in component_matches:
            components[f'src/components/{name}.js'] = code.strip()
            logger.debug(f"Extracted component src/components/{name}.js")
        
        # Extract component CSS files
        component_css_matches = re.findall(component_css_pattern, text)
        if not component_css_matches:
            # Try fallback pattern
            logger.info("No CSS component matches with primary pattern, trying fallback pattern")
            component_css_matches = re.findall(component_css_fallback_pattern, text)
                
        for name, code in component_css_matches:
            components[f'src/components/{name}.css'] = code.strip()
            logger.debug(f"Extracted CSS src/components/{name}.css")
        
        # Additional fallback: look for code blocks that might be components but not properly formatted
        if len(component_matches) == 0:
            logger.warning("No component files found with standard patterns. Attempting deep extraction...")
            # Look for code blocks that might contain component definitions
            js_blocks = re.findall(r'```(?:javascript|js)\s*([\s\S]*?)```', text)
            
            for i, block in enumerate(js_blocks):
                # Look for React component patterns
                if ('import React' in block or 'function ' in block) and 'export default' in block:
                    # Try to determine the component name
                    name_match = re.search(r'function\s+([A-Za-z][A-Za-z0-9_]*)', block)
                    if name_match:
                        name = name_match.group(1)
                        components[f'src/components/{name}.js'] = block.strip()
                        logger.info(f"Deep extraction: Found component {name} in unformatted block")
                    else:
                        # Use a generic name
                        components[f'src/components/Component{i+1}.js'] = block.strip()
                        logger.info(f"Deep extraction: Created generic component Component{i+1}")
        
        # NEW CODE: Filter out generic components if proper named components exist
        component_files = [k for k in components.keys() if k.startswith('src/components/')]
        named_components = [k for k in component_files if not re.match(r'src/components/Component\d+\.js', k)]
        
        # If we have proper named components, remove generic ones
        if named_components:
            logger.info(f"Found {len(named_components)} named components, removing generic components")
            for key in list(components.keys()):
                if re.match(r'src/components/Component\d+\.js', key):
                    logger.info(f"Removing generic component {key} as named components exist")
                    del components[key]
        
        logger.info(f"Extracted {len(components)} total components")
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
        
        # Check if response contains HTML instead of code
        if generated_text.strip().lower().startswith("<!doctype html") or "<html" in generated_text.lower():
            logger.error("Received HTML response instead of code")
            raise ValueError("API returned HTML instead of fixed code. Check API quota or permissions.")
        
        # Extract code block
        import re
        code_match = re.search(r'```(?:javascript|js|css)?\s*([\s\S]*?)```', generated_text)
        if code_match:
            return code_match.group(1).strip()
        
        return generated_text.strip()

# Initialize the helper
gemini_helper = GeminiHelper()
