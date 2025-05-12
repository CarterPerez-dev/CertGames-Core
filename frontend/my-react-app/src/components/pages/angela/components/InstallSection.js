// frontend/my-react-app/src/components/pages/angela/components/InstallSection.js
import React, { useState, useRef, useEffect } from 'react';
import styled from '@emotion/styled';
import { keyframes } from '@emotion/react';
import { 
  FaDownload, 
  FaDocker, 
  FaTools, 
  FaPython, 
  FaCheck, 
  FaTerminal,
  FaCopy
} from 'react-icons/fa';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import ExpansionEffect from '../animations/ExpansionEffects';

// Glow animation for copy button success
const glowAnimation = keyframes`
  0% {
    box-shadow: 0 0 0 0 rgba(51, 255, 51, 0.4);
  }
  70% {
    box-shadow: 0 0 0 10px rgba(51, 255, 51, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(51, 255, 51, 0);
  }
`;

// Hover animation for buttons
const hoverAnimation = keyframes`
  0% {
    transform: translateY(0);
  }
  100% {
    transform: translateY(-2px);
  }
`;

// Main container for the installation section
const InstallSectionContainer = styled.section`
  width: 100%;
  position: relative;
  
  /* Background pattern */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-image: 
      linear-gradient(rgba(51, 51, 51, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(51, 51, 51, 0.05) 1px, transparent 1px);
    background-size: 20px 20px;
    z-index: -1;
    opacity: 0.2;
  }
`;

// Inner container to maintain max-width and centering
const InstallSectionInner = styled.div`
  max-width: 1200px;
  margin: 0 auto;
  padding: 5rem 2rem;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    padding: 3rem 1rem;
  }
`;

// Section title with 8-bit styling
const SectionTitle = styled.h2`
  font-family: ${THEME.typography.fontFamilySecondary};
  font-size: 3rem;
  color: ${THEME.colors.textPrimary};
  text-align: center;
  margin-bottom: 1rem;
  text-transform: uppercase;
  letter-spacing: ${THEME.typography.spacingWide};
  position: relative;
  
  &::after {
    content: "";
    position: absolute;
    bottom: -1rem;
    left: 50%;
    transform: translateX(-50%);
    width: 80px;
    height: 4px;
    background-color: ${THEME.colors.accentPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 2.25rem;
  }
`;

// Section subtitle
const SectionSubtitle = styled.p`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.2rem;
  color: ${THEME.colors.textSecondary};
  text-align: center;
  max-width: 800px;
  margin: 2rem auto;
  line-height: 1.6;
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1rem;
  }
`;

// Installation method tabs container
const InstallTabs = styled.div`
  display: flex;
  justify-content: center;
  margin-bottom: 2rem;
  position: relative;
  
  /* Bottom border */
  &::after {
    content: "";
    position: absolute;
    bottom: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 100%;
    max-width: 600px;
    height: 1px;
    background: linear-gradient(
      to right,
      transparent 0%,
      ${THEME.colors.borderPrimary} 15%,
      ${THEME.colors.borderPrimary} 85%,
      transparent 100%
    );
  }
`;

// Individual installation tab
const InstallTab = styled.button`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  padding: 0.75rem 1.5rem;
  background-color: ${props => props.active ? THEME.colors.bgTertiary : THEME.colors.bgSecondary};
  color: ${props => props.active ? THEME.colors.textPrimary : THEME.colors.textSecondary};
  border: 2px solid ${props => props.active ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  position: relative;
  
  /* Top border highlight when active */
  ${props => props.active && `
    &::after {
      content: "";
      position: absolute;
      bottom: -2px;
      left: 0;
      right: 0;
      height: 2px;
      background-color: ${THEME.colors.bgTertiary};
      z-index: 2;
    }
  `}
  
  &:first-of-type {
    border-radius: 4px 0 0 4px;
  }
  
  &:last-of-type {
    border-radius: 0 4px 4px 0;
  }
  
  &:hover {
    background-color: ${props => props.active ? THEME.colors.bgTertiary : THEME.colors.bgTertiary};
    color: ${THEME.colors.textPrimary};
    animation: ${hoverAnimation} 0.2s forwards;
  }
  
  /* Icon styling */
  svg {
    font-size: 1.1rem;
    color: ${props => props.active ? THEME.colors.accentPrimary : THEME.colors.textSecondary};
  }
  
  @media (max-width: ${THEME.breakpoints.sm}) {
    font-size: 0.9rem;
    padding: 0.5rem 1rem;
    
    /* Hide text on small screens, show only icons */
    .tab-text {
      display: none;
    }
  }
`;

// Code block container with pixel art styling
const CodeBlock = styled.div`
  position: relative;
  background-color: ${THEME.colors.bgCodeBlock};
  border: 2px solid ${THEME.colors.borderPrimary};
  padding: 1.5rem;
  margin: 2rem auto;
  max-width: 800px;
  overflow-x: auto;
  border-radius: 8px;
  
  /* Shadow for depth */
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
  
  /* Pixelated corners */
  &::after {
    content: "";
    position: absolute;
    top: -2px;
    left: -2px;
    right: -2px;
    bottom: -2px;
    z-index: -1;
    border: 2px solid ${THEME.colors.bgSecondary};
    clip-path: polygon(
      0% 8px, 8px 8px, 8px 0%, calc(100% - 8px) 0%, calc(100% - 8px) 8px, 100% 8px, 
      100% calc(100% - 8px), calc(100% - 8px) calc(100% - 8px), calc(100% - 8px) 100%, 
      8px 100%, 8px calc(100% - 8px), 0% calc(100% - 8px)
    );
  }
  
  /* Shell prompt indicator */
  &::before {
    content: ">_";
    position: absolute;
    top: -12px;
    left: 15px;
    background-color: ${THEME.colors.bgCodeBlock};
    color: ${THEME.colors.accentPrimary};
    padding: 0 8px;
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 0.9rem;
  }
`;

// Code content with terminal styling
const Code = styled.pre`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.9rem;
  color: ${THEME.colors.textPrimary};
  overflow-x: auto;
  white-space: pre-wrap;
  margin: 0;
  
  .comment {
    display: block;
    color: ${THEME.colors.textTertiary};
    margin-bottom: 0.5rem;
  }
  
  .command {
    display: block;
    color: ${THEME.colors.terminalGreen};
    margin-bottom: 0.25rem;
  }
  
  /* Improved scrollbar styling */
  &::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  
  &::-webkit-scrollbar-track {
    background: ${THEME.colors.bgSecondary};
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-thumb {
    background: ${THEME.colors.borderPrimary};
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-thumb:hover {
    background: ${THEME.colors.accentPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.8rem;
  }
`;

// Copy button with animation
const CopyButton = styled.button`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background-color: ${props => props.copied ? THEME.colors.terminalGreen : THEME.colors.bgSecondary};
  color: ${props => props.copied ? THEME.colors.bgPrimary : THEME.colors.textSecondary};
  border: 1px solid ${props => props.copied ? THEME.colors.terminalGreen : THEME.colors.borderPrimary};
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.8rem;
  padding: 0.4rem 0.8rem;
  cursor: pointer;
  transition: all 0.2s ease;
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  
  ${props => props.copied && `
    animation: ${glowAnimation} 2s infinite;
  `}
  
  &:hover {
    background-color: ${props => props.copied ? THEME.colors.terminalGreen : THEME.colors.bgTertiary};
    color: ${props => props.copied ? THEME.colors.bgPrimary : THEME.colors.textPrimary};
    transform: translateY(-2px);
  }
  
  svg {
    font-size: 0.9rem;
  }
`;

// Requirements section with improved visual styling
const RequirementsContainer = styled.div`
  margin: 3rem auto;
  max-width: 800px;
  padding: 2rem;
  background-color: ${THEME.colors.bgSecondary}40;
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: 8px;
  position: relative;
  
  /* Subtle box shadow */
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
  
  /* Decorative corner */
  &::before {
    content: "";
    position: absolute;
    top: 0;
    right: 0;
    width: 24px;
    height: 24px;
    border-top: 2px solid ${THEME.colors.accentPrimary};
    border-right: 2px solid ${THEME.colors.accentPrimary};
  }
`;

// Requirements heading
const RequirementsTitle = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  
  svg {
    color: ${THEME.colors.accentPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// List of system requirements
const Requirements = styled.ul`
  list-style-type: none;
  padding: 0;
  
  li {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 1rem;
    color: ${THEME.colors.textSecondary};
    padding: 0.5rem 0 0.5rem 2rem;
    position: relative;
    
    &::before {
      content: "•";
      position: absolute;
      left: 0.5rem;
      color: ${THEME.colors.accentPrimary};
      font-size: 1.2rem;
    }
    
    strong {
      color: ${THEME.colors.textPrimary};
      font-weight: ${THEME.typography.weightSemibold};
    }
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    li {
      font-size: 0.9rem;
    }
  }
`;

// Next steps container
const NextSteps = styled.div`
  margin: 3rem auto;
  max-width: 800px;
  padding: 2rem;
  background-color: ${THEME.colors.bgSecondary}40;
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: 8px;
  position: relative;
  
  /* Subtle box shadow */
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
  
  /* Decorative corner */
  &::before {
    content: "";
    position: absolute;
    bottom: 0;
    left: 0;
    width: 24px;
    height: 24px;
    border-bottom: 2px solid ${THEME.colors.accentPrimary};
    border-left: 2px solid ${THEME.colors.accentPrimary};
  }
`;

// Next steps title
const NextStepsTitle = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  
  svg {
    color: ${THEME.colors.accentPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 1.25rem;
  }
`;

// Next steps list
const NextStepsList = styled.ol`
  padding-left: 1.5rem;
  counter-reset: steps;
  
  li {
    font-family: ${THEME.typography.fontFamilyPrimary};
    font-size: 1rem;
    color: ${THEME.colors.textSecondary};
    padding: 0.75rem 0;
    position: relative;
    counter-increment: steps;
    margin-bottom: 0.5rem;
    
    &::before {
      content: counter(steps);
      position: absolute;
      left: -1.5rem;
      top: 0.75rem;
      width: 24px;
      height: 24px;
      background-color: ${THEME.colors.accentPrimary}30;
      color: ${THEME.colors.textPrimary};
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.9rem;
    }
    
    code {
      font-family: ${THEME.typography.fontFamilyPrimary};
      background-color: ${THEME.colors.bgCodeBlock};
      padding: 0.2em 0.4em;
      border-radius: 3px;
      font-size: 0.9em;
      color: ${THEME.colors.terminalGreen};
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    li {
      font-size: 0.9rem;
      
      &::before {
        width: 20px;
        height: 20px;
        font-size: 0.8rem;
      }
    }
  }
`;

// Installation code for different methods
const INSTALL_METHODS = {
  quick: `# Quick Install (Recommended)
curl -sSL https://raw.githubusercontent.com/CarterPerez-dev/angela-cli/main/scripts/install-quick.sh | bash`,
  
  manual: `# Clone the repository
git clone https://github.com/CarterPerez-dev/angela-cli.git
cd angela-cli

# Install the package
pip install -e .

# Set up shell integration for Bash
echo 'source "$(python -c "import os, angela; print(os.path.join(os.path.dirname(angela.__file__), \\"shell/angela.bash\\"))")"' >> ~/.bashrc
source ~/.bashrc

# Or for Zsh
# echo 'source "$(python -c "import os, angela; print(os.path.join(os.path.dirname(angela.__file__), \\"shell/angela.zsh\\"))")"' >> ~/.zshrc
# source ~/.zshrc`,
  
  docker: `# Pull the Docker image
docker pull angela-cli/angela:latest

# Run Angela CLI in a container
docker run -it --rm -v $(pwd):/workspace angela-cli/angela:latest`,
  
  virtualenv: `# Create a virtual environment
python -m venv ~/angela-env

# Activate it
source ~/angela-env/bin/activate

# Install Angela
pip install angela-cli

# Set up shell integration
echo 'source ~/angela-env/lib/python3.9/site-packages/angela/shell/angela.bash' >> ~/.bashrc
source ~/.bashrc`
};

/**
 * InstallSection Component
 * 
 * Displays installation instructions for Angela CLI with different methods.
 */
const InstallSection = () => {
  const [activeMethod, setActiveMethod] = useState('quick');
  const [copied, setCopied] = useState(false);
  const [copyTimeout, setCopyTimeout] = useState(null);
  const codeRef = useRef(null);
  
  // Clear copy timeout on unmount
  useEffect(() => {
    return () => {
      if (copyTimeout) clearTimeout(copyTimeout);
    };
  }, [copyTimeout]);
  
  // Handle tab change
  const handleMethodChange = (method) => {
    setActiveMethod(method);
    setCopied(false);
    if (copyTimeout) clearTimeout(copyTimeout);
  };
  
  // Handle copy to clipboard
  const handleCopy = async () => {
    if (codeRef.current) {
      try {
        await navigator.clipboard.writeText(INSTALL_METHODS[activeMethod]);
        setCopied(true);
        
        // Reset copied state after 2 seconds
        const timeout = setTimeout(() => {
          setCopied(false);
        }, 2000);
        
        setCopyTimeout(timeout);
      } catch (err) {
        console.error('Failed to copy: ', err);
      }
    }
  };
  
  // Format code with syntax highlighting
  const formatCode = (code) => {
    return code.split('\n').map((line, index) => {
      if (line.startsWith('#')) {
        return <span key={index} className="comment">{line}</span>;
      } else {
        return <span key={index} className="command">{line}</span>;
      }
    }).reduce((prev, curr, i) => [prev, <br key={`br-${i}`} />, curr]);
  };
  
  return (
    <InstallSectionContainer id="install">
      <InstallSectionInner>
        <SectionTitle>Installation</SectionTitle>
        
        <SectionSubtitle>
          Angela CLI offers several installation methods. Choose the one that best fits your needs and environment.
        </SectionSubtitle>
        
        <InstallTabs>
          <InstallTab 
            active={activeMethod === 'quick'} 
            onClick={() => handleMethodChange('quick')}
          >
            <FaDownload />
            <span className="tab-text">Quick Install</span>
          </InstallTab>
          <InstallTab 
            active={activeMethod === 'manual'} 
            onClick={() => handleMethodChange('manual')}
          >
            <FaTerminal />
            <span className="tab-text">Manual</span>
          </InstallTab>
          <InstallTab 
            active={activeMethod === 'docker'} 
            onClick={() => handleMethodChange('docker')}
          >
            <FaDocker />
            <span className="tab-text">Docker</span>
          </InstallTab>
          <InstallTab 
            active={activeMethod === 'virtualenv'} 
            onClick={() => handleMethodChange('virtualenv')}
          >
            <FaPython />
            <span className="tab-text">Virtual Env</span>
          </InstallTab>
        </InstallTabs>
        
        <ExpansionEffect type="pulse" active={true} speed="normal">
          <CodeBlock>
            <CopyButton 
              onClick={handleCopy}
              copied={copied}
            >
              {copied ? (
                <>
                  <FaCheck /> Copied
                </>
              ) : (
                <>
                  <FaCopy /> Copy
                </>
              )}
            </CopyButton>
            <Code ref={codeRef}>
              {formatCode(INSTALL_METHODS[activeMethod])}
            </Code>
          </CodeBlock>
        </ExpansionEffect>
        
        <RequirementsContainer>
          <RequirementsTitle>
            <FaTools /> System Requirements
          </RequirementsTitle>
          <Requirements>
            <li><strong>Python:</strong> 3.9 or higher</li>
            <li><strong>Operating System:</strong> Linux, macOS, WSL (Windows Subsystem for Linux)</li>
            <li><strong>Shell:</strong> Bash or Zsh (primary support), Fish (limited support)</li>
            <li><strong>Terminal:</strong> Any modern terminal emulator with UTF-8 support</li>
            <li><strong>API Access:</strong> Internet connection for Gemini API access</li>
          </Requirements>
        </RequirementsContainer>
        
        <NextSteps>
          <NextStepsTitle>
            <FaTerminal /> Getting Started
          </NextStepsTitle>
          <NextStepsList>
            <li>
              After installation, run the initial setup to configure your API key and preferences:
              <br />
              <code>angela init</code>
            </li>
            <li>
              Try a simple command to verify Angela is working:
              <br />
              <code>angela "help"</code>
            </li>
            <li>
              Explore file operations:
              <br />
              <code>angela "find all Python files in the current directory"</code>
            </li>
            <li>
              Get creative with multi-step operations:
              <br />
              <code>angela "create a feature branch for user authentication and set up a basic structure"</code>
            </li>
            <li>
              Explore the full documentation to discover all features:
              <br />
              <code>angela "show me examples of advanced workflows"</code>
            </li>
          </NextStepsList>
        </NextSteps>
      </InstallSectionInner>
    </InstallSectionContainer>
  );
};

export default InstallSection;
