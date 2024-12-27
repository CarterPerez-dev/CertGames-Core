import React, { useState } from 'react';
import './Resources.css'; 



const redditSubreddits = [
  { name: 'r/CompTIA', url: 'https://www.reddit.com/r/CompTIA/' },
  { name: 'r/CyberSecurity', url: 'https://www.reddit.com/r/cybersecurity/' },
  { name: 'r/AskNetsec', url: 'https://www.reddit.com/r/AskNetsec/' },
  { name: 'r/Casp', url: 'https://www.reddit.com/r/casp/' },
  { name: 'r/ITCareerQuestions', url: 'https://www.reddit.com/r/ITCareerQuestions/' },
  { name: 'r/WGU', url: 'https://www.reddit.com/r/WGU/' },
  { name: 'r/CCNA', url: 'https://www.reddit.com/r/ccna/' },
  { name: 'r/sysadmin', url: 'https://www.reddit.com/r/sysadmin/' },
  { name: 'r/linuxquestions/', url: 'https://www.reddit.com/r/linuxquestions/' },
  { name: 'r/netsec', url: 'https://www.reddit.com/r/netsec/' },
  { name: 'r/ReverseEngineering', url: 'https://www.reddit.com/r/ReverseEngineering/' },
  { name: 'r/BlueTeamSec', url: 'https://www.reddit.com/r/BlueTeamSec/' },
  { name: 'r/RedTeam', url: 'https://www.reddit.com/r/RedTeam/' },
  { name: 'r/InformationSecurity', url: 'https://www.reddit.com/r/InformationSecurity/' },
  { name: 'r/ethicalhacking', url: 'https://www.reddit.com/r/ethicalhacking/' },
  { name: 'r/ITsecurity', url: 'https://www.reddit.com/r/ITsecurity/' },
  { name: 'r/netsecstudents', url: 'https://www.reddit.com/r/netsecstudents/' },
];

const redditPosts = [
  { title: '#', url: '#' },



];

const youtubeChannels = [
  { name: 'Professor Messer', url: 'https://www.youtube.com/@professormesser' },
  { name: 'NetworkChuck', url: 'https://www.youtube.com/@NetworkChuck' },
  { name: 'PowerCertAnimatedVideos', url: 'https://www.youtube.com/@PowerCertAnimatedVideos' },
  { name: 'HackerSploit', url: 'https://www.youtube.com/@HackerSploit' },
  { name: 'Cyberkraft', url: 'https://www.youtube.com/@cyberkraft' },
  { name: 'howtonetwork', url: 'https://www.youtube.com/@howtonetworkcom' },
  { name: 'MyCS1', url: 'https://www.youtube.com/@MyCS1/videos' },
  { name: 'CBT Nuggets', url: 'https://www.youtube.com/user/cbtnuggets' },
  { name: 'Eli the Computer Guy', url: 'https://www.youtube.com/user/elithecomputerguy' },
  { name: 'The Cyber Mentor', url: 'https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw' },
  { name: 'David Bombal', url: 'https://www.youtube.com/user/soloRaining' },
  { name: 'Jason Dion', url: 'https://www.youtube.com/user/jasoncdion' },
  { name: 'ITProTV', url: 'https://www.youtube.com/user/ITProTV' },
  { name: 'freeCodeCamp.org', url: 'https://www.youtube.com/freecodecamp' },
];

const youtubeVideos = [
  { title: 'How to Pass your 220-1101 and 220-1102 A+ Exams - CompTIA A+ 220-1101', url: 'https://www.youtube.com/watch?v=87t6P5ZHTP0&list=PLG49S3nxzAnnOmvg5UGVenB_qQgsh01uC' },
  { title: 'CompTIA A+ Full Course - FREE - [31+ Hours]', url: 'https://www.youtube.com/watch?v=1CZXXNKAY5o&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=5' },
  { title: 'CompTIA A+ Certification Practice Test 2024 (Exam 220-1101) (40 Questions with Explained Answers)', url: 'https://www.youtube.com/watch?v=e16It3eYHgc&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=10' },
  { title: 'How to Pass Your N10-008 Network+ Exam', url: 'https://www.youtube.com/watch?v=As6g6IXcVa4&list=PLG49S3nxzAnlCJiCrOYuRYb6cne864a7G' },
  { title: 'Computer Networking Course - Network Engineering [CompTIA Network+ Exam Prep]', url: 'https://www.youtube.com/watch?v=qiQR5rTSshw&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=6' },
  { title: 'Networking basics (2024) | What is a switch, router, gateway, subnet, gateway, firewall & DMZ', url: 'https://www.youtube.com/watch?v=_IOZ8_cPgu8&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=7' },
  { title: 'How to Pass Your SY0-701 Security+ Exam', url: 'https://www.youtube.com/watch?v=KiEptGbnEBc&list=PLG49S3nxzAnl4QDVqK-hOnoqcSKEIDDuv' },
  { title: 'Security+ Certification SY0-701 50 Practice Questions', url: 'https://www.youtube.com/watch?v=yPqSLJG8Rt0&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=2' },
  { title: 'CompTIA Security+ SY0-701. 50 Exam Practice Question', url: 'https://www.youtube.com/watch?v=2qrPJbL9G6c&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=14' },
  { title: 'CompTIA Security+ SY0-701 - Series Intro & Exam Prep Strategy', url: 'https://www.youtube.com/watch?v=1E7pI7PB4KI&list=PL7XJSuT7Dq_UDJgYoQGIW9viwM5hc4C7n' },
  { title: 'CompTIA CySA+ // 2024 Crash Course // 10+ Hours for FREE', url: 'https://www.youtube.com/watch?v=qP9x0mucwVc&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=9' },
  { title: 'COMPTIA Pentest+ Course Preparation TryHackMe', url: 'https://www.youtube.com/watch?v=cADW_cUJni0&list=PLqM63j87R5p4olmWpzqaXMhEP2zEnQhPD' },
  { title: 'What is Subnetting? - Subnetting Mastery  NOTE: I HIGHLY RECOMMEND!', url: 'https://www.youtube.com/watch?v=BWZ-MHIhqjM&list=PLIFyRwBY_4bQUE4IB5c4VPRyDoLgOdExE' },
  { title: 'IT Security Certifications: CySA+ vs PenTest+ vs CISSP', url: 'https://www.youtube.com/watch?v=YhCvNARSPo4' },
  { title: 'Ethical Hacking in 15 Hours - 2023 Edition - Learn to Hack! (Part 1)', url: 'https://www.youtube.com/watch?v=3FNYvj2U0HM&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=13' },
  { title: 'Paypal - Live bug bounty hunting on Hackerone | Live Recon | part 2', url: 'https://www.youtube.com/watch?v=Dtx4kNXj0OQ&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=11' },
  { title: 'Complete Ethical hacking course 16 hours | ethical hacking full course with practical | Zero to Hero', url: 'https://www.youtube.com/watch?v=w_oxcjPOWos&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=4' },
  { title: 'Full Ethical Hacking Course - Network Penetration Testing for Beginners (2019)', url: 'https://www.youtube.com/watch?v=3Kq1MIfTWCE&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=3' },
  { title: 'How to Get an IT Job Without Experience', url: 'https://www.youtube.com/watch?v=XkTNQCtuRPY&list=PLG49S3nxzAnkUvxTH_ANPYQWGo9wYlz7h' },
  { title: 'Start your IT Career with the CompTIA Trifecta? A+, Net+, Sec+', url: 'https://www.youtube.com/watch?v=IBKW0s20T8o&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=12' },
  { title: 'How I Would Learn Cyber Security if I Could Start Over in 2024 (Beginner Roadmap)', url: 'https://www.youtube.com/watch?v=b12JrM-6DBY&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=15' },
  { title: 'Network Protocols - ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DNS, DHCP - Networking Fundamentals - L6', url: 'https://www.youtube.com/watch?v=E5bSumTAHZE&list=PLejqXniG-4qmFqpxbWd7Oo235uH1ffG2x&index=16' },
  { title: 'Network Devices - Hosts, IP Addresses, Networks - Networking Fundamentals', url: 'https://www.youtube.com/watch?v=bj-Yfakjllc&list=PLIFyRwBY_4bRLmKfP1KnZA6rZbRHtxmXi' },
  { title: 'Python Full Course for free 🐍 (2024)', url: 'https://www.youtube.com/watch?v=ix9cRaBkVe0' },
  
  
];

const udemyCourses = [
  { title: '#', url: '#' },
 
];

const linkedInPeople = [
  { name: '#', url: '#' },
  
];

const otherResources = [
  { name: '*VERY IMPORTANT FOR CASP* -wyzguyscybersecurity blog', url: 'https://wyzguyscybersecurity.com/new-insights-for-the-casp-cas-004-exam/' },
  { name: 'Official CompTIA Resources', url: 'https://www.comptia.org/resources' },
  { name: 'Cybrary', url: 'https://www.cybrary.it' },
  { name: 'OWASP Official Site', url: 'https://owasp.org' },
  { name: 'Pluralsight', url: 'https://www.pluralsight.com/' },
  { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/' },
  { name: 'Dark Reading', url: 'https://www.darkreading.com/' },
  { name: 'SANS Institute', url: 'https://www.sans.org/' },
  { name: 'InfoSec Institute', url: 'https://www.infosecinstitute.com/' },
  { name: 'Hack The Box', url: 'https://www.hackthebox.com/' },
  { name: 'TryHackMe', url: 'https://tryhackme.com/' },
  { name: 'Security Weekly', url: 'https://securityweekly.com/' },
];

const comptiaObjectives = [
  { cert: 'A+ Core 1', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-a-220-1101-exam-objectives-(3-0)' },
  { cert: 'A+ Core 2', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-a-220-1102-exam-objectives-(3-0)' },
  { cert: 'Network+ (N10-009)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-network-n10-009-exam-objectives-(4-0)' },
  { cert: 'Security+ (701)', url: 'https://certblaster.com/wp-content/uploads/2023/11/CompTIA-Security-SY0-701-Exam-Objectives-1.pdf' },
  { cert: 'CySA+ (003)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-cysa-cs0-003-exam-objectives-2-0.pdf' },
  { cert: 'CASP+ (004)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-casp-cas-004-exam-objectives-(4-0)' },
  { cert: 'PenTest+ (002)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-pentest-pt0-002-exam-objectives-(4-0)' },
  { cert: 'Cloud+ (003)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-cloud-cv0-003-exam-objectives-(1-0)#:~:text=%EE%80%80CompTIA%EE%80%81%20exams%20result%20from%20subject%20matter' },
  { cert: 'Cloud Essentials', url: 'https://partners.comptia.org/docs/default-source/resources/cloud-essentials-certification-guide' },
  { cert: 'Linux+ (005)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-linux-xk0-005-exam-objectives-(1-0)' },
  { cert: 'Data+ (001)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-data-da0-001-exam-objectives-(2-0)' },
  { cert: 'DataSys+', url: 'https://partners.comptia.org/certifications/datasys' },
  { cert: 'DataX+', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-datax-dy0-001-exam-objectives-(5-0)' },
  { cert: 'Server+ (005)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-server-sk0-005-exam-objectives' },
  { cert: 'Project+ (005)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-project-pk0-005-exam-objectives-(2-0)' },
  { cert: 'ITF', url: 'https://www.comptia.jp/pdf/CompTIA%20IT%20Fundamentals%20FC0-U61%20Exam%20Objectives.pdf' },
  { cert: 'Tech+', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-tech-fc0-u71-exam-objectives-(1-2)' },
  { cert: 'SecurityX (CASP 005)', url: 'https://partners.comptia.org/docs/default-source/resources/comptia-securityx-cas-005-exam-objectives-(3-0)' }

];

const securityFrameworks = [
  { name: 'NIST Cybersecurity Framework', url: 'https://www.nist.gov/cyberframework' },
  { name: 'ISO/IEC 27001', url: 'https://www.iso.org/isoiec-27001-information-security.html' },
  { name: 'Lockheed Martin Cyber Kill Chain', url: 'https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html' },
  { name: 'MITRE ATT&CK Framework', url: 'https://attack.mitre.org/' },
  { name: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' },
  { name: 'COBIT', url: 'https://www.isaca.org/resources/cobit' },
  { name: 'ITIL (Information Technology Infrastructure Library)', url: 'https://www.itlibrary.org/' },
  { name: 'PCI-DSS (Payment Card Industry Data Security Standard)', url: 'https://www.pcisecuritystandards.org/' },
  { name: 'HIPAA Security Rule', url: 'https://www.hhs.gov/hipaa/for-professionals/security/index.html' },
  { name: 'Sarbanes-Oxley (SOX) IT Controls', url: 'https://www.sarbanes-oxley-101.com/sarbanes-oxley-compliance.htm' },
  { name: 'FedRAMP', url: 'https://www.fedramp.gov/' },
  { name: 'CIS Controls', url: 'https://www.cisecurity.org/controls' },
  { name: 'ENISA (European Union Agency for Cybersecurity) Guidelines', url: 'https://www.enisa.europa.eu/' },
  { name: 'SANS Top 20 Critical Controls', url: 'https://www.cm-alliance.com/consultancy/compliance-gap-analysis/sans-top-20-controls/' },
  { name: 'Cybersecurity Maturity Model Certification (CMMC)', url: 'https://www.acq.osd.mil/cmmc/' },
  { name: 'FISMA (Federal Information Security Management Act)', url: 'https://www.cisa.gov/topics/cyber-threats-and-advisories/federal-information-security-modernization-act' },
  { name: 'NERC CIP', url: 'https://www.nerc.com/pa/CI/tpv5impmntnstdy/CIPV5_FAQs_Consolidated_Oct2015_Oct_13_2015.pdf' },
  { name: 'GDPR (General Data Protection Regulation)', url: 'https://gdpr.eu/' },
  { name: 'HITRUST CSF', url: 'https://hitrustalliance.net/' },
  { name: 'ISO/IEC 27002', url: 'https://www.iso.org/standard/73906.html' },
  { name: 'NIST 800-53 Security Controls', url: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' },
  { name: 'NIST 800-171', url: 'https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final' },
  { name: 'Unified Kill Chain', url: 'https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf' },
  { name: 'VERIS', url: 'http://veriscommunity.net/' },
  { name: 'Diamond Model of Intrusion Analysis', url: 'https://www.threatintel.academy/wp-content/uploads/2020/07/diamond-model.pdf' },
  { name: 'ATT&CK for ICS', url: 'https://collaborate.mitre.org/attackics/index.php/Main_Page' },
  { name: 'SOC2', url: 'https://www.vanta.com/products/soc-2' },
  { name: 'ISO 22301 (Business Continuity)', url: 'https://www.iso.org/iso-22301-business-continuity.html' },
  { name: 'ISO/IEC 27004 (Information Security Management — Monitoring, Measurement, Analysis, and Evaluation)', url: 'https://www.iso.org/standard/42505.html' },
  { name: 'ISO/IEC 27006 (Requirements for Bodies Providing Audit and Certification of Information Security Management Systems)', url: 'https://www.iso.org/standard/43506.html' },
  { name: 'ISO/IEC 27007 (Guidelines for Information Security Management Systems Auditing)', url: 'https://www.iso.org/standard/44375.html' },
  { name: 'ISO/IEC 27008 (Guidance for Auditors on Information Security Controls)', url: 'https://www.iso.org/standard/50518.html' },
  { name: 'ISO/IEC 27011 (Information Security Management Guidelines for Telecommunications Organizations)', url: 'https://www.iso.org/standard/43755.html' },
  { name: 'ISO/IEC 27013 (Guidance on the Integrated Implementation of ISO/IEC 27001 and ISO/IEC 20000-1)', url: 'https://www.iso.org/standard/68427.html' },
  { name: 'ISO/IEC 27014 (Governance of Information Security)', url: 'https://www.iso.org/standard/43756.html' },
  { name: 'ISO/IEC 27031 (Guidelines for Information and Communication Technology Readiness for Business Continuity)', url: 'https://www.iso.org/standard/44374.html' },
  { name: 'ISO/IEC 27032 (Guidelines for Cybersecurity)', url: 'https://www.iso.org/standard/44375.html' },
  { name: 'ISO/IEC 27033 (Network Security)', url: 'https://www.iso.org/standard/63411.html' },
  { name: 'ISO/IEC 27034 (Application Security)', url: 'https://www.iso.org/standard/44379.html' },
  { name: 'ISO/IEC 27041 (Guidelines on Assuring Suitability and Adequacy of Incident Investigative Methods)', url: 'https://www.iso.org/standard/44403.html' },
  { name: 'ISO/IEC 27042 (Guidelines on Digital Evidence Analysis)', url: 'https://www.iso.org/standard/44404.html' },
  { name: 'ISO/IEC 27043 (Incident Investigation Principles and Processes)', url: 'https://www.iso.org/standard/44405.html' },
  { name: 'ISO/IEC 27044 (Guidelines for Security Information and Event Management)', url: 'https://www.iso.org/standard/44406.html' },
  { name: 'ISO/IEC 29100 (Privacy Framework)', url: 'https://www.iso.org/standard/45123.html' },
  { name: 'ISO/IEC 29134 (Guidelines for Privacy Impact Assessment)', url: 'https://www.iso.org/standard/62289.html' },
  { name: 'ISO/IEC 29151 (Code of Practice for Personally Identifiable Information Protection)', url: 'https://www.iso.org/standard/62725.html' },
  { name: 'ISO/IEC 38500 (Governance of IT for the Organization)', url: 'https://www.iso.org/standard/51639.html' },
  { name: 'NIST SP 800-160 (Systems Security Engineering)', url: 'https://csrc.nist.gov/publications/detail/sp/800-160/vol-1/final' },
  { name: 'NIST SP 800-190 (Application Container Security Guide)', url: 'https://csrc.nist.gov/publications/detail/sp/800-190/final' },
  { name: 'NIST SP 800-207 (Zero Trust Architecture)', url: 'https://csrc.nist.gov/publications/detail/sp/800-207/final' },
  { name: 'NIST SP 800-218 (Secure Software Development Framework)', url: 'https://csrc.nist.gov/publications/detail/sp/800-218/final' },
  { name: 'NIST SP 800-53A (Assessing Security and Privacy Controls in Federal Information Systems and Organizations)', url: 'https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final' },
  { name: 'NIST SP 800-63 (Digital Identity Guidelines)', url: 'https://pages.nist.gov/800-63-3/' },
  { name: 'NIST SP 800-37 (Risk Management Framework for Information Systems and Organizations)', url: 'https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final' },
  { name: 'NIST SP 800-39 (Managing Information Security Risk)', url: 'https://csrc.nist.gov/publications/detail/sp/800-39/final' },
  { name: 'NIST SP 800-61 (Computer Security Incident Handling Guide)', url: 'https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final' },
  { name: 'NIST SP 800-88 (Guidelines for Media Sanitization)', url: 'https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final' },
  { name: 'NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment)', url: 'https://csrc.nist.gov/publications/detail/sp/800-115/final' },
  { name: 'NIST SP 800-184 (Guide for Cybersecurity Event Recovery)', url: 'https://csrc.nist.gov/publications/detail/sp/800-184/final' },
  { name: 'NIST SP 800-30 (Guide for Conducting Risk Assessments)', url: 'https://csrc.nist.gov/publications/detail/sp/800-30/rev-a/final' },
  { name: 'NIST SP 800-64 (Security Considerations in the System Development Life Cycle)', url: 'https://csrc.nist.gov/publications/detail/sp/800-64/rev-2/final' },
  { name: 'NIST SP 800-83 (Guide to Malware Incident Prevention and Handling)', url: 'https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final' },
  { name: 'NIST SP 800-92 (Guide to Computer Security Log Management)', url: 'https://csrc.nist.gov/publications/detail/sp/800-92/final' },
  { name: 'NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems)', url: 'https://csrc.nist.gov/publications/detail/sp/800-94/rev-1/draft' },
  { name: 'NIST SP 800-100 (Information Security Handbook: A Guide for Managers)', url: 'https://csrc.nist.gov/publications/detail/sp/800-100/final' },
  { name: 'NIST SP 800-122 (Guide to Protecting the Confidentiality of Personally Identifiable Information)', url: 'https://csrc.nist.gov/publications/detail/sp/800-122/final' },
  { name: 'NIST SP 800-137 (Information Security Continuous Monitoring for Federal Information Systems and Organizations)', url: 'https://csrc.nist.gov/publications/detail/sp/800-137/final' },
  { name: 'NIST SP 800-144 (Guidelines on Security and Privacy in Public Cloud Computing)', url: 'https://csrc.nist.gov/publications/detail/sp/800-144/final' },
  { name: 'NIST SP 800-146 (Cloud Computing Synopsis and Recommendations)', url: 'https://csrc.nist.gov/publications/detail/sp/800-146/final' },
  { name: 'NIST SP 800-150 (Guide to Cyber Threat Information Sharing)', url: 'https://csrc.nist.gov/publications/detail/sp/800-150/final' },
  { name: 'NIST SP 800-160 (Systems Security Engineering: Considerations for a Multidisciplinary Approach in the Engineering of Trustworthy Secure Systems)', url: 'https://csrc.nist.gov/publications/detail/sp/800-160/vol-1/final' },
  { name: 'NIST SP 800-171A (Assessing Security Requirements for Controlled Unclassified Information)', url: 'https://csrc.nist.gov/publications/detail/sp/800-171a/final' },
  { name: 'NIST SP 800-181 (National Initiative for Cybersecurity Education (NICE) Cybersecurity Workforce Framework)', url: 'https://csrc.nist.gov/publications/detail/sp/800-181/rev-1/final' },
  { name: 'Cyber Essentials (UK Cybersecurity Standard)', url: 'https://www.ncsc.gov.uk/cyberessentials/overview' },
  { name: 'Essential Eight (Australian Cybersecurity Framework)', url: 'https://www.cyber.gov.au/acsc/view-all-content/essential-eight' },
  { name: 'Secure Controls Framework (SCF)', url: 'https://www.securecontrolsframework.com/' },
  { name: 'Factor Analysis of Information Risk (FAIR)', url: 'https://www.fairinstitute.org/' },
  { name: 'Cloud Security Alliance (CSA) STAR', url: 'https://cloudsecurityalliance.org/star/' },
  { name: 'NIST Privacy Framework', url: 'https://www.nist.gov/privacy-framework' },
  { name: 'ISF Standard of Good Practice for Information Security', url: 'https://www.securityforum.org/solutions-and-insights/the-standard-of-good-practice-for-information-security/' },
  { name: 'TOGAF (The Open Group Architecture Framework)', url: 'https://www.opengroup.org/togaf' },
  { name: 'IEC 62443 (Industrial Automation and Control Systems Security)', url: 'https://webstore.iec.ch/publication/7028' },
  { name: 'FFIEC Cybersecurity Assessment Tool', url: 'https://www.ffiec.gov/cyberassessmenttool.htm' },
  { name: 'SWIFT Customer Security Programme (CSP)', url: 'https://www.swift.com/myswift/customer-security-programme-csp' },
  { name: 'AI Risk Management Framework (AI RMF)', url: 'https://www.nist.gov/itl/ai-risk-management-framework' },
  { name: 'BSI IT-Grundschutz (German Federal Office for Information Security)', url: 'https://www.bsi.bund.de/EN/Topics/IT-Grundschutz/it-grundschutz_node.html' },
  { name: 'Canadian Centre for Cyber Security’s IT Security Guidance', url: 'https://cyber.gc.ca/en/guidance' },
  { name: 'TISAX (Trusted Information Security Assessment Exchange)', url: 'https://enx.com/tisax/' },
  { name: 'MARISSA (Maritime Cybersecurity Standards)', url: 'https://www.maritimecybersecurity.center/' },
  { name: 'ANSI/ISA-62443 (Cybersecurity Standards for Automation)', url: 'https://www.isa.org/standards-and-publications/isa-standards/isa-62443-series-of-standards' },
  { name: 'UK Government Minimum Cyber Security Standard', url: 'https://www.gov.uk/government/publications/minimum-cyber-security-standard' },
  { name: 'Basel Committee on Banking Supervision (BCBS 239)', url: 'https://www.bis.org/bcbs/publ/d239.htm' },
  { name: 'OECD Guidelines for the Security of Information Systems and Networks', url: 'https://www.oecd.org/sti/ieconomy/15582260.pdf' },
  { name: 'CERT Resilience Management Model (CERT-RMM)', url: 'https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099' },
  { name: 'NESA Information Assurance Standards (UAE IAS)', url: 'https://www.nesa.ae/' },
  { name: 'Hong Kong Monetary Authority (HKMA) Cybersecurity Fortification Initiative', url: 'https://www.hkma.gov.hk/eng/key-functions/banking/cybersecurity-fortification-initiative-cfi/' },
  { name: 'K-ISMS (Korean Information Security Management System)', url: 'https://www.kisa.or.kr/eng/main.jsp' },
  { name: 'Japan Cybersecurity Framework (J-CSIP)', url: 'https://www.ipa.go.jp/security/english/jcsip.html' },
  { name: 'NATO Cyber Defence Policy Framework', url: 'https://www.nato.int/cps/en/natohq/topics_78170.htm' },
  { name: 'DHS Continuous Diagnostics and Mitigation (CDM) Program', url: 'https://www.cisa.gov/cdm' },
  { name: 'World Economic Forum (WEF) Cybersecurity Principles', url: 'https://www.weforum.org/reports/principles-for-board-governance-of-cyber-risk' },
  { name: 'HITRUST Threat Catalogue', url: 'https://hitrustalliance.net/hitrust-threat-catalog/' },
  { name: 'Digital Geneva Convention Cyber Norms', url: 'https://digitalpeace.microsoft.com/' },
  { name: 'Smart Grid Interoperability Panel (SGIP) Cybersecurity Guidelines', url: 'https://www.nist.gov/publications/nist-framework-and-roadmap-smart-grid-interoperability-standards-release-30' },
  { name: 'APEC Privacy Framework', url: 'https://www.apec.org/Publications/2017/08/APEC-Privacy-Framework-(2015)' },
  { name: 'NERC PRC Standards', url: 'https://www.nerc.com/pa/Stand/Pages/PRC-Reliability-Standards.aspx' },
  { name: 'Digital Identity Authentication and Fraud Prevention Framework', url: 'https://www.gsma.com/identity/digital-identity-programme/' },
  { name: 'Zero Trust Architecture', url: 'https://csrc.nist.gov/publications/detail/sp/800-207/final' },
  { name: 'MITRE Shield', url: 'https://shield.mitre.org/' },
  { name: 'MITRE Engage', url: 'https://engage.mitre.org/' },
  { name: 'NIST Cybersecurity Workforce Framework', url: 'https://www.nist.gov/cyberframework/workforce' },
];

const capitalizeFirstLetter = (string) => {
  return string.charAt(0).toUpperCase() + string.slice(1);
};


const resourcesData = {
  reddit: [
    ...redditSubreddits,
    ...redditPosts.map((post) => ({ name: post.title, url: post.url }))
  ],
  youtube: [
    ...youtubeChannels,
    ...youtubeVideos.map((vid) => ({ name: vid.title, url: vid.url }))
  ],
  udemy: udemyCourses.map((course) => ({ name: course.title, url: course.url })),
  frameworks: [...securityFrameworks],
  other: [...otherResources],
  linkedin: [...linkedInPeople],

  'CompTIA Certification Objectives': comptiaObjectives.map((obj) => ({ name: obj.cert, url: obj.url })),


  'A+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().includes('a+ core'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'A+ Study Guide', url: 'https://www.examcompass.com/comptia/a-plus-certification/free-a-plus-practice-tests' },
    { name: 'A+ Practice Exams', url: 'https://www.examcompass.com/comptia/a-plus-certification/free-a-plus-practice-tests' },
    { name: 'Professor Messer\'s A+ Videos', url: 'https://www.youtube.com/playlist?list=PLEttE3jOf4oRW_qbN-VqVt5pYb0COgD49' },
    { name: 'CompTIA A+ Labs', url: 'https://www.itsupportresume.com/labs-for-comptia-a-plus/' },
    { name: 'CompTIA A+ Official Practice Tests', url: 'https://www.comptia.org/certifications/a/practice-tests' },
  ],


  'Network+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('network+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'Network+ Study Guide', url: 'https://www.examcompass.com/comptia/network-plus-certification/free-network-plus-practice-tests' },
    { name: 'Network+ Labs', url: 'https://www.netacad.com/courses/networking/networking-lab-resources' },
    { name: 'Network+ Practice Exams', url: 'https://www.comptia.org/certifications/network/practice-tests' },
    { name: 'Professor Messer\'s Network+ Videos', url: 'https://www.youtube.com/playlist?list=PLEttE3jOf4oRgkxF62g6N6OIp50lR6QEz' },

  ],


  'Security+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('security+') && !obj.cert.toLowerCase().includes('x'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'Security+ Study Guide', url: '#' },
    { name: 'Security+ Practice Labs', url: '#' },
    { name: 'Security+ Practice Exams', url: '#'},
    { name: 'Professor Messer\'s Security+ Videos', url: '#' },

  ],


  'CySA+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('cysa+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'CySA+ Study Guide', url: '#' },
    { name: 'CySA+ Practice Exams', url: '#' },
    { name: 'CySA+ Labs and Exercises', url: '#' },


  ],


  'SecurityX/CASP': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().includes('casp') || obj.cert.toLowerCase().includes('securityx'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'CASP+ Study Guide', url: 'https://www.examcompass.com/comptia/casp-plus-certification/free-casp-plus-practice-tests' },
    { name: 'SecurityX Practice Labs', url: 'https://www.cybrary.it/course/comptia-casp-plus/' },
    { name: 'CASP+ Practice Exams', url: 'https://www.comptia.org/certifications/casp/practice-tests' },
    { name: 'Advanced SecurityX Training', url: 'https://www.youtube.com/watch?v=exampleSecurityXTraining' },

  ],


  'PenTest+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('pentest+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'PenTest+ Study Guide', url: 'https://www.examcompass.com/comptia/pentest-plus-certification/free-pentest-plus-practice-tests' },
    { name: 'PenTest+ Labs', url: 'https://www.hackthebox.com/' },
    { name: 'PenTest+ Practice Exams', url: 'https://www.comptia.org/certifications/pentest/practice-tests' },
    { name: 'HackerSploit PenTest+ Training', url: 'https://www.youtube.com/watch?v=examplePenTestPlusTraining' },

  ],


  'Cloud+/Cloud Essentials': [

    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().includes('cloud'))
      .map(obj => ({ name: obj.cert, url: obj.url })),

    { name: 'Cloud+ Study Guide', url: 'https://www.examcompass.com/comptia/cloud-plus-certification/free-cloud-plus-practice-tests' },
    { name: 'Cloud Essentials Training', url: 'https://www.comptia.org/certifications/cloud/overview' },
    { name: 'Cloud+ Practice Labs', url: 'https://www.aws.training/' },
    { name: 'Pluralsight Cloud+ Courses', url: 'https://www.pluralsight.com/paths/comptia-cloud-plus' },

  ],


  'Linux+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('linux+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),

    { name: 'Linux+ Study Guide', url: 'https://www.examcompass.com/comptia/linux-plus-certification/free-linux-plus-practice-tests' },
    { name: 'Linux+ Practice Labs', url: 'https://www.virtualbox.org/' },
    { name: 'Linux+ Practice Exams', url: 'https://www.comptia.org/certifications/linux/practice-tests' },
    { name: 'Linux+ Training by CBT Nuggets', url: 'https://www.udemy.com/course/comptia-linux-plus/' },

  ],


  'Data+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('data'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'Data+ Study Guide', url: 'https://www.examcompass.com/comptia/data-plus-certification/free-data-plus-practice-tests' },
    { name: 'Data+ Practice Exams', url: 'https://www.comptia.org/certifications/data/practice-tests' },
    { name: 'Data+ Training on Cybrary', url: 'https://www.cybrary.it/course/comptia-data-plus/' },
    { name: 'Data+ Labs and Exercises', url: 'https://www.datacamp.com/' },

  ],


  'Server+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('server+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'Server+ Study Guide', url: 'https://www.examcompass.com/comptia/server-plus-certification/free-server-plus-practice-tests' },
    { name: 'Server+ Labs', url: 'https://www.vmware.com/products/vsphere.html' },
    { name: 'Server+ Practice Exams', url: 'https://www.comptia.org/certifications/server/practice-tests' },
    { name: 'Server+ Training on Pluralsight', url: 'https://www.pluralsight.com/courses/comptia-server-plus-fundamentals' },

  ],


  'Project+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('project+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'Project+ Study Guide', url: 'https://www.examcompass.com/comptia/project-plus-certification/free-project-plus-practice-tests' },
    { name: 'Project+ Practice Exams', url: 'https://www.comptia.org/certifications/project/practice-tests' },
    { name: 'Project+ Training on Udemy', url: 'https://www.udemy.com/course/comptia-project-plus/' },
    { name: 'Project Management Essentials', url: 'https://www.coursera.org/specializations/project-management' },

  ],


  'ITF/TECH+': [
    ...comptiaObjectives
      .filter(obj => obj.cert.toLowerCase().startsWith('itf') || obj.cert.toLowerCase().includes('tech+'))
      .map(obj => ({ name: obj.cert, url: obj.url })),
    { name: 'ITF Study Guide', url: 'https://www.examcompass.com/comptia-itf-certification/free-itf-practice-tests' },
    { name: 'Tech+ Training Videos', url: 'https://www.youtube.com/playlist?list=PLr6-GrHUlVf0uIra4Hpph5OZyTbX_0i6m' },
    { name: 'ITF/TECH+ Practice Exams', url: 'https://www.comptia.org/certifications/itf/practice-tests' },
    { name: 'Tech+ Labs and Exercises', url: 'https://www.virtualbox.org/' },
    
  ]
};



function Resources() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [sorted, setSorted] = useState(false);
  const [randomResource, setRandomResource] = useState(null);

  const handleSearch = (event) => setSearchTerm(event.target.value.toLowerCase());
  const handleCategoryChange = (event) => setSelectedCategory(event.target.value);

  // Filtering Resources Based on Search and Category
  const filteredResources = Object.entries(resourcesData)
    .filter(([category]) => selectedCategory === "all" || category === selectedCategory)
    .flatMap(([, resources]) => resources)
    .filter((resource) => resource.name.toLowerCase().includes(searchTerm))
    .sort((a, b) => (sorted ? a.name.localeCompare(b.name) : 0));

  // Handling Random Resource Selection
  const handleRandomResource = () => {
    const currentCategoryResources = selectedCategory === "all"
      ? Object.values(resourcesData).flat()
      : (resourcesData[selectedCategory] || []);
    
    if (currentCategoryResources.length === 0) {
      setRandomResource(null);
      return;
    }
    
    const random = currentCategoryResources[Math.floor(Math.random() * currentCategoryResources.length)];
    setRandomResource(random);
  };

return (
    // Apply the resources-background class to wrap the entire component
    <div className="resources-background">
      <div className="resources-container">
        <h1 className="resources-header">Cybersecurity Resources Hub</h1>

        {/* Controls Section */}
        <div className="resources-controls">
          <input
            type="text"
            placeholder="Search resources..."
            value={searchTerm}
            onChange={handleSearch}
            className="search-input"
          />

          <select
            onChange={handleCategoryChange}
            value={selectedCategory}
            className="category-select"
          >
            <option value="all">All Categories</option>
            {Object.keys(resourcesData).map((category) => (
              <option key={category} value={category}>
                {capitalizeFirstLetter(category)}
              </option>
            ))}
          </select>

          <button
            onClick={() => setSorted(!sorted)}
            className="sort-button"
          >
            {sorted ? "Unsort" : "Sort A-Z"}
          </button>

          <button
            onClick={handleRandomResource}
            className="random-button"
          >
            Random Resource
          </button>
        </div>

        {/* Random Resource Section */}
        {randomResource && (
          <div className="resources-random-resource">
            <h2>Explore This Resource:</h2>
            <a
              href={randomResource.url}
              target="_blank"
              rel="noopener noreferrer"
            >
              {randomResource.name}
            </a>
          </div>
        )}

        {/* Resources List */}
        <ul className="resources-list">
          {filteredResources.length ? (
            filteredResources.map((resource, index) => (
              <li key={index}>
                <a
                  href={resource.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {resource.name}
                </a>
              </li>
            ))
          ) : (
            <p>No resources found.</p>
          )}
        </ul>
      </div>
    </div>
  );
};

export default Resources;


