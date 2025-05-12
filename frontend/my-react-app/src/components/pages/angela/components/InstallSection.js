// frontend/my-react-app/src/components/pages/angela/components/InstallSection.js
import React, { useState, useRef } from 'react';
import styled from '@emotion/styled';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';
import ExpansionEffect from '../animations/ExpansionEffects';

// Main container for the installation section
const InstallSectionContainer = styled.section`
  padding: 4rem 2rem;
  position: relative;
  
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
  margin-bottom: 3rem;
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
  max-width: 700px;
  margin: 0 auto 2rem;
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
`;

// Individual installation tab
const InstallTab = styled.button`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1rem;
  padding: 0.75rem 1.5rem;
  background-color: ${props => props.active ? THEME.colors.accentPrimary : THEME.colors.bgSecondary};
  color: ${props => props.active ? THEME.colors.textPrimary : THEME.colors.textSecondary};
  border: 2px solid ${props => props.active ? THEME.colors.accentPrimary : THEME.colors.borderPrimary};
  cursor: pointer;
  transition: all 0.2s ease;
  
  &:first-of-type {
    border-radius: 4px 0 0 4px;
  }
  
  &:last-of-type {
    border-radius: 0 4px 4px 0;
  }
  
  &:hover {
    background-color: ${props => props.active ? THEME.colors.accentPrimary : THEME.colors.bgTertiary};
    color: ${THEME.colors.textPrimary};
  }
  
  @media (max-width: ${THEME.breakpoints.sm}) {
    font-size: 0.9rem;
    padding: 0.5rem 1rem;
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
  border-radius: 4px;
  
  // Pixelated corners
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
`;

// Code content with terminal styling
const Code = styled.pre`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.9rem;
  color: ${THEME.colors.textPrimary};
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  
  .command {
    color: ${THEME.colors.terminalGreen};
  }
  
  .comment {
    color: ${THEME.colors.textTertiary};
  }
  
  @media (max-width: ${THEME.breakpoints.md}) {
    font-size: 0.8rem;
  }
`;

// Copy button with animation
const CopyButton = styled.button`
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  background-color: ${THEME.colors.bgSecondary};
  color: ${THEME.colors.textSecondary};
  border: 1px solid ${THEME.colors.borderPrimary};
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 0.8rem;
  padding: 0.4rem 0.8rem;
  cursor: pointer;
  transition: all 0.2s ease;
  
  &:hover {
    background-color: ${THEME.colors.bgTertiary};
    color: ${THEME.colors.textPrimary};
  }
  
  &.copied {
    background-color: ${THEME.colors.terminalGreen};
    color: ${THEME.colors.bgPrimary};
  }
`;

// Requirements list with 8-bit styling
const RequirementsList = styled.div`
  margin: 2rem auto;
  max-width: 800px;
`;

// Requirements heading
const RequirementsTitle = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1rem;
  
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
  background-color: ${THEME.colors.bgSecondary}80;
  border: 1px solid ${THEME.colors.borderPrimary};
  border-radius: 4px;
`;

// Next steps title
const NextStepsTitle = styled.h3`
  font-family: ${THEME.typography.fontFamilyPrimary};
  font-size: 1.5rem;
  color: ${THEME.colors.textPrimary};
  margin-bottom: 1.5rem;
  
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
    
    &::before {
      content: counter(steps);
      position: absolute;
      left: -1.5rem;
      top: 0.75rem;
      width: 24px;
      height: 24px;
      background-color: ${THEME.colors.accentPrimary}50;
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
  const codeRef = useRef(null);
  
  // Handle tab change
  const handleMethodChange = (method) => {
    setActiveMethod(method);
    setCopied(false);
  };
  
  // Handle copy to clipboard
  const handleCopy = async () => {
    if (codeRef.current) {
      try {
        await navigator.clipboard.writeText(INSTALL_METHODS[activeMethod]);
        setCopied(true);
        
        // Reset copied state after 2 seconds
        setTimeout(() => {
          setCopied(false);
        }, 2000);
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
    <InstallSectionContainer>
      <SectionTitle>Installation</SectionTitle>
      
      <SectionSubtitle>
        Angela CLI offers several installation methods. Choose the one that best fits your needs and environment.
      </SectionSubtitle>
      
      <InstallTabs>
        <InstallTab 
          active={activeMethod === 'quick'} 
          onClick={() => handleMethodChange('quick')}
        >
          Quick Install
        </InstallTab>
        <InstallTab 
          active={activeMethod === 'manual'} 
          onClick={() => handleMethodChange('manual')}
        >
          Manual
        </InstallTab>
        <InstallTab 
          active={activeMethod === 'docker'} 
          onClick={() => handleMethodChange('docker')}
        >
          Docker
        </InstallTab>
        <InstallTab 
          active={activeMethod === 'virtualenv'} 
          onClick={() => handleMethodChange('virtualenv')}
        >
          Virtual Env
        </InstallTab>
      </InstallTabs>
      
      <ExpansionEffect type="pulse" active={true} speed="normal">
        <CodeBlock>
          <CopyButton 
            onClick={handleCopy}
            className={copied ? 'copied' : ''}
          >
            {copied ? 'Copied!' : 'Copy'}
          </CopyButton>
          <Code ref={codeRef}>
            {formatCode(INSTALL_METHODS[activeMethod])}
          </Code>
        </CodeBlock>
      </ExpansionEffect>
      
      <RequirementsList>
        <RequirementsTitle>System Requirements</RequirementsTitle>
        <Requirements>
          <li><strong>Python:</strong> 3.9 or higher</li>
          <li><strong>Operating System:</strong> Linux, macOS, WSL (Windows Subsystem for Linux)</li>
          <li><strong>Shell:</strong> Bash or Zsh (primary support), Fish (limited support)</li>
          <li><strong>Terminal:</strong> Any modern terminal emulator with UTF-8 support</li>
          <li><strong>API Access:</strong> Internet connection for Gemini API access</li>
        </Requirements>
      </RequirementsList>
      
      <NextSteps>
        <NextStepsTitle>Getting Started</NextStepsTitle>
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
    </InstallSectionContainer>
  );
};

export default InstallSection;
