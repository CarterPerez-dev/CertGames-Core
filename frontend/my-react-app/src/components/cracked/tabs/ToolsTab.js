// src/components/cracked/tabs/ToolsTab.js
import React from "react";
import {
  FaTools, FaDatabase, FaEnvelope, FaCloud, FaGoogle, FaApple, 
  FaCreditCard, FaServer, FaPaintBrush, FaGithub,
  FaFacebook, FaReddit, FaLinkedin, FaTwitter, FaInstagram, FaTiktok,
  FaLink, FaShieldAlt, FaExternalLinkAlt, FaBrain, FaPalette, FaCode, FaGlobe
} from "react-icons/fa";
import { SiMongodb, SiSendgrid, SiCloudflare, SiGooglecloud, SiGoogleadsense, 
  SiAppstore, SiOpenai, SiStripe, SiOracle, SiExpo, SiCanva, SiChatbot, 
  SiGnometerminal, SiX, SiClaude, SiChainguard, SiGmail } from "react-icons/si";

const ToolsTab = () => {
  // Tool categories with their respective tools
  const toolCategories = [
    {
      id: "cloud",
      name: "Cloud & Infrastructure",
      icon: <FaCloud color="#cc0000" />,
      tools: [
        { name: "MongoDB Atlas", url: "https://cloud.mongodb.com/v2/679b028e1f33b201d14aaf18#/overview", icon: <SiMongodb />, color: "#13AA52" },
        { name: "Cloudflare", url: "https://dash.cloudflare.com/50b62d49d4439d599f871dc471c5ccc8/home/domains", icon: <SiCloudflare />, color: "#F48120" },
        { name: "Google Cloud Console", url: "https://console.cloud.google.com/auth/overview?invt=AbuAfg&authuser=1&project=oauth-453018", icon: <SiGooglecloud />, color: "#4285F4" },
        { name: "Oracle Cloud", url: "https://www.oracle.com/cloud/sign-in.html", icon: <SiOracle />, color: "#C74634" }
      ]
    },
    {
      id: "developer",
      name: "Development Tools",
      icon: <FaCode color="#cc0000" />,
      tools: [
        { name: "GitHub (Web App)", url: "https://github.com/CarterPerez-dev/ProxyAuthRequired/tree/main", icon: <FaGithub />, color: "#989898" },
        { name: "GitHub (iOS App)", url: "https://github.com/CarterPerez-dev/certgames", icon: <FaGithub />, color: "#FFFFFF" },
        { name: "Expo Dev", url: "https://expo.dev/accounts/certgames/projects/CertGamesApp", icon: <SiExpo />, color: "#FFFFFF" },
        { name: "Apple App Connect", url: "https://appstoreconnect.apple.com/apps", icon: <SiAppstore />, color: "#0D96F6" },
        { name: "Apple Developer", url: "https://developer.apple.com/account/resources/profiles/list", icon: <FaApple />, color: "#A2AAAD" },
        { name: "Icloud", url: "https://www.icloud.com/", icon: <FaGlobe />, color: "#318CE7" }
      ]
    },
    {
      id: "marketing",
      name: "Marketing & Design",
      icon: <FaPaintBrush color="#cc0000" />,
      tools: [
        { name: "SendGrid", url: "https://login.sendgrid.com/login/identifier", icon: <SiSendgrid />, color: "#1A82E2" },
        { name: "Google Admin Console", url: "https://admin.google.com/u/7/ac/home?rapt=AEjHL4PtrsNfMeR5U6Q9z9HG0VEX7RznDWYVZUF-Cy5egPZoXPXPMvUaTBERXS_oAsfNPj3Dcyxi7DrNKta4WzXDSGU1DzADdcDeuB7XPAHj2hjFfyapCTo", icon: <FaGoogle />, color: "#4C8BF5" },
        { name: "Google Search Console", url: "https://search.google.com/u/1/search-console?resource_id=sc-domain%3Acertgames.com", icon: <SiGoogleadsense />, color: "#034694" },
        { name: "Canva", url: "https://www.canva.com/", icon: <SiCanva />, color: "#99FFFF" },
        { name: "Stripe", url: "https://dashboard.stripe.com/acct_1R3wAfBeeXPGfjzr/test/workbench/overview", icon: <SiStripe />, color: "#635BFF" },
        { name: "Gmail", url: "https://mail.google.com/mail/u/5/#inbox", icon: <SiGmail />, color: "#DB4437" }
      ]
    },
    {
      id: "ai",
      name: "AI Tools",
      icon: <FaBrain color="#cc0000" />,
      tools: [
        { name: "Claude", url: "https://claude.ai/chat/", icon: <SiClaude />, color: "#E3963E" },
        { name: "ChatGPT", url: "https://chatgpt.com/", icon: <SiOpenai />, color: "#FFFFFF" },
        { name: "OpenAI Admin", url: "https://platform.openai.com/logs", icon: <SiOpenai />, color: "#00BFFF" },
        { name: "Gemini AI Studio", url: "https://aistudio.google.com/", icon: <SiGnometerminal />, color: "#1877F2" },
        { name: "Grok 3", url: "https://grok.com/?referrer=website", icon: <SiX />, color: "#B8B8B8" },
        { name: "DeepSeek", url: "https://chat.deepseek.com/", icon: <SiChainguard />, color: "#1E88E5" }
      ]
    },
    {
      id: "social",
      name: "Social Media",
      icon: <FaLink color="#cc0000" />,
      tools: [
        { name: "Facebook", url: "https://www.facebook.com/people/CertGames/61574087485497/", icon: <FaFacebook />, color: "#1877F2" },
        { name: "Reddit", url: "https://www.reddit.com/user/Hopeful_Beat7161/", icon: <FaReddit />, color: "#FF4500" },
        { name: "LinkedIn", url: "https://www.linkedin.com/company/certgames/?viewAsMember=true", icon: <FaLinkedin />, color: "#0A66C2" },
        { name: "Twitter (X)", url: "https://x.com/CertsGamified", icon: <SiX />, color: "#000000" },
        { name: "Instagram", url: "https://www.instagram.com/certsgamified/", icon: <FaInstagram />, color: "#E4405F" },
        { name: "TikTok", url: "https://www.tiktok.com/@certgames.com", icon: <FaTiktok />, color: "#FFFFFF" }
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
                  <div className="tool-icon" style={{ color: tool.color }}>
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
