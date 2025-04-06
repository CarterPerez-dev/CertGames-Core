// src/components/cracked/tabs/ToolsTab.js
import React from "react";
import {
  FaTools, FaDatabase, FaEnvelope, FaCloud, FaGoogle, FaApple, 
  FaCreditCard, FaServer, FaPaintBrush, FaRobot, FaGithub,
  FaFacebook, FaReddit, FaLinkedin, FaTwitter, FaInstagram, FaTiktok,
  FaLink, FaShieldAlt, FaExternalLinkAlt, FaBrain, FaComments, 
  FaPalette, FaCode
} from "react-icons/fa";
import { SiMongodb, SiSendgrid, SiCloudflare, SiGooglecloud, SiGoogleadsense, 
  SiAppstore, SiOpenai, SiStripe, SiOracle, SiExpo, SiCanva, SiChatbot, 
  SiGemini, SiX } from "react-icons/si";

const ToolsTab = () => {
  // Tool categories with their respective tools
  const toolCategories = [
    {
      id: "cloud",
      name: "Cloud & Infrastructure",
      icon: <FaCloud />,
      tools: [
        { name: "MongoDB Atlas", url: "https://cloud.mongodb.com/v2/679b028e1f33b201d14aaf18#/overview", icon: <SiMongodb /> },
        { name: "Cloudflare", url: "https://dash.cloudflare.com/50b62d49d4439d599f871dc471c5ccc8/home/domains", icon: <SiCloudflare /> },
        { name: "Google Cloud Console", url: "https://console.cloud.google.com/auth/overview?invt=AbuAfg&authuser=1&project=oauth-453018", icon: <SiGooglecloud /> },
        { name: "Oracle Cloud", url: "https://www.oracle.com/cloud/sign-in.html", icon: <SiOracle /> }
      ]
    },
    {
      id: "developer",
      name: "Development Tools",
      icon: <FaCode />,
      tools: [
        { name: "GitHub (Web App)", url: "https://github.com/CarterPerez-dev/ProxyAuthRequired/tree/main", icon: <FaGithub /> },
        { name: "GitHub (iOS App)", url: "https://github.com/CarterPerez-dev/certgames", icon: <FaGithub /> },
        { name: "Expo Dev", url: "https://expo.dev/accounts/certgames/projects/CertGamesApp", icon: <SiExpo /> },
        { name: "Apple App Connect", url: "https://appstoreconnect.apple.com/apps", icon: <SiAppstore /> },
        { name: "Apple Developer", url: "https://developer.apple.com/account/resources/profiles/list", icon: <FaApple /> }
      ]
    },
    {
      id: "marketing",
      name: "Marketing & Design",
      icon: <FaPaintBrush />,
      tools: [
        { name: "SendGrid", url: "https://login.sendgrid.com/login/identifier", icon: <SiSendgrid /> },
        { name: "Google Admin Console", url: "https://admin.google.com/u/7/ac/home?rapt=AEjHL4PtrsNfMeR5U6Q9z9HG0VEX7RznDWYVZUF-Cy5egPZoXPXPMvUaTBERXS_oAsfNPj3Dcyxi7DrNKta4WzXDSGU1DzADdcDeuB7XPAHj2hjFfyapCTo", icon: <FaGoogle /> },
        { name: "Google Search Console", url: "https://search.google.com/u/1/search-console?resource_id=sc-domain%3Acertgames.com", icon: <SiGoogleadsense /> },
        { name: "Canva", url: "https://www.canva.com/", icon: <SiCanva /> },
        { name: "Stripe", url: "https://dashboard.stripe.com/acct_1R3wAfBeeXPGfjzr/test/workbench/overview", icon: <SiStripe /> }
      ]
    },
    {
      id: "ai",
      name: "AI Tools",
      icon: <FaBrain />,
      tools: [
        { name: "Claude", url: "https://claude.ai/chat/", icon: <FaRobot /> },
        { name: "ChatGPT", url: "https://chatgpt.com/", icon: <SiChatbot /> },
        { name: "OpenAI Admin", url: "https://platform.openai.com/logs", icon: <SiOpenai /> },
        { name: "Gemini AI Studio", url: "https://aistudio.google.com/", icon: <SiGemini /> },
        { name: "Grok 3", url: "https://grok.com/?referrer=website", icon: <FaBrain /> },
        { name: "DeepSeek", url: "https://chat.deepseek.com/", icon: <FaComments /> }
      ]
    },
    {
      id: "social",
      name: "Social Media",
      icon: <FaLink />,
      tools: [
        { name: "Facebook", url: "https://www.facebook.com/people/CertGames/61574087485497/", icon: <FaFacebook /> },
        { name: "Reddit", url: "https://www.reddit.com/user/Hopeful_Beat7161/", icon: <FaReddit /> },
        { name: "LinkedIn", url: "https://www.linkedin.com/company/certgames/?viewAsMember=true", icon: <FaLinkedin /> },
        { name: "Twitter (X)", url: "https://x.com/CertsGamified", icon: <SiX /> },
        { name: "Instagram", url: "https://www.instagram.com/certsgamified/", icon: <FaInstagram /> },
        { name: "TikTok", url: "https://www.tiktok.com/@certgames.com", icon: <FaTiktok /> }
      ]
    }
  ];

  // Open link in new tab
  const openLink = (url) => {
    window.open(url, "_blank", "noopener,noreferrer");
  };

  return (
    <div className="admin-tab-content tools-tab">
      <div className="admin-content-header">
        <h2><FaTools /> External Tools Dashboard</h2>
      </div>

      <div className="tools-tab-intro">
        <p>Quick access to all external platforms and services used for CertGames operations and development.</p>
      </div>

      <div className="tools-categories">
        {toolCategories.map(category => (
          <div className="tools-category-section" key={category.id}>
            <div className="tools-category-header">
              <div className="tools-category-icon">
                {category.icon}
              </div>
              <h3>{category.name}</h3>
            </div>
            <div className="tools-grid">
              {category.tools.map((tool, index) => (
                <div className="tool-card" key={index} onClick={() => openLink(tool.url)}>
                  <div className="tool-icon">
                    {tool.icon}
                  </div>
                  <div className="tool-info">
                    <h4 className="tool-name">{tool.name}</h4>
                    <div className="tool-link">
                      <FaExternalLinkAlt />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ToolsTab;
