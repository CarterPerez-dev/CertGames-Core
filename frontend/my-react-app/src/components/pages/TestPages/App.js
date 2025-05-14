import React from 'react';
import Header from './Header';
import Hero from './Hero';
import About from './About';
import Education from './Education';
import Experience from './Experience';
import Skills from './Skills';
import Projects from './Projects';
import Contact from './Contact';
import Footer from './Footer';
import './index.css';
// Main application component that orchestrates the layout of the portfolio
const Apptest = () => {
  // Placeholder data for the job seeker
  const portfolioData = {
    name: "Alex Doe",
    title: "Cybersecurity Professional",
    contact: {
      email: "alex.doe@example.com",
      linkedin: "https://linkedin.com/in/alexdoe",
      github: "https://github.com/alexdoe"
    },
    education: [
      {
        institution: "University of Maryland Global Campus",
        degree: "Masters in Cybersecurity",
        years: "2021 - 2023",
        description: "Focused on advanced cybersecurity principles, threat management, and secure systems design."
      },
      {
        institution: "Anne Arundel Community College",
        degree: "Associate of Applied Science in Cybersecurity",
        years: "2018 - 2020",
        description: "Completed foundational coursework in networking, information security, and IT systems."
      }
    ],
    experience: [
      {
        company: "Cyber Solutions Inc.",
        role: "Junior Security Analyst",
        years: "Jan 2023 - Present",
        responsibilities: [
          "Monitored security alerts and responded to incidents.",
          "Assisted in vulnerability assessments and penetration testing.",
          "Contributed to the development of security policies and procedures."
        ]
      },
      {
        company: "Tech Support Co.",
        role: "IT Support Specialist",
        years: "Jun 2020 - Dec 2022",
        responsibilities: [
          "Provided technical support to end-users.",
          "Managed user accounts and permissions.",
          "Assisted with network troubleshooting and maintenance."
        ]
      }
    ],
    skills: {
      technical: ["Network Security", "SIEM Tools (e.g., Splunk)", "Vulnerability Assessment", "Penetration Testing Basics", "Incident Response", "Cryptography", "Python", "Linux/Unix", "Firewall Configuration", "IDS/IPS"],
      soft: ["Problem Solving", "Analytical Thinking", "Communication", "Teamwork", "Attention to Detail"]
    },
    projects: [
      {
        title: "Home Network Security Monitor",
        description: "Developed a Python-based tool to monitor home network traffic for suspicious activity and generate alerts. Utilized Scapy for packet sniffing and analysis.",
        technologies: ["Python", "Scapy", "SQLite"],
        link: "#",
        repo: "#"
      },
      {
        title: "Secure Web Application Audit",
        description: "Conducted a comprehensive security audit of a sample web application, identifying vulnerabilities such as XSS and SQL injection, and proposed mitigation strategies.",
        technologies: ["OWASP ZAP", "Burp Suite (Community)", "Manual Testing"],
        link: "#",
      },
      {
        title: "CTF Challenge Platform",
        description: "Contributed to a team project building a small Capture The Flag (CTF) platform with various cybersecurity challenges for educational purposes.",
        technologies: ["Docker", "Flask (Python)", "HTML/CSS", "JavaScript"],
        repo: "#"
      }
    ]
  };

  return (
    <>
      <Header name={portfolioData.name} />
      <main>
        <Hero name={portfolioData.name} title={portfolioData.title} />
        <About />
        <Education items={portfolioData.education} />
        <Experience items={portfolioData.experience} />
        <Skills skills={portfolioData.skills} />
        <Projects items={portfolioData.projects} />
        <Contact contactInfo={portfolioData.contact} />
      </main>
      <Footer name={portfolioData.name} />
    </>
  );
}

export default Apptest;
