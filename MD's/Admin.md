So i need to add an admin interface, it will have its own login and will be a serpate path called "cracked" so /cracked. it will just have a password i enter (im gonna mae it very lon) and ill put the password in the .env and make it an .env like authkey or something. keep in mind when we make the login we must use very unique name fro the fucntions/cssc classes/backedn routes etc tec because we already haev a regualr login for normal users so we have to enure they dont affect one another. ALso i would liek to add a support page/question page in my web app where users can ask me any questiosn they want like a chatbot and ask anything from website support, what on the exams, anything of the sort and it will go to my admin interfece adn ill repodnf (like i said it will be a chatbot so ill be the other user answering evryhign) and teh messages have to be perstant per user so i guess we have to store the questions in my databse so the user can logout/refresh teh page etc etc and the chat still be there. also each user will obviosly have there own chat thing its not globably hared across all users (all users get to chat but they dont intersect with each other its there own messagre to me)

so heres kinda what the admin interface will be abel to do


# Admin Interface

### 1. **Dashboard Overview**

- **Key Metrics:**  
  - Total active users, new registrations (daily/weekly/monthly)
  - Test completions, average test scores, number of test attempts
  - Daily bonus claims and daily PBQ (question) responses  
  - Revenue or coin transaction summaries (if applicable)
  - thing where i can answer the qustions from people asking me int he support page

- **Performance Monitoring:**  
  - Real-time stats on API response times and database query latencies  
  - Error rates and logs summary  
  - Graphs/charts (using libraries like Chart.js or Recharts) to visualize trends over time

- **Alerts & Notifications:**  
  - Automatic alerts for suspicious activity (e.g. multiple failed login attempts)
  - Notifications for performance anomalies or potential issues

---

### 2. **User Management**

- **User Listing & Search:**  
  - A searchable, filterable list of users (by username, email, registration date, etc.)
  - Ability to view detailed profiles (including coin balance, test history, last login, and bonus claim time)

- **Account Actions:**  
  - Options to delete, suspend, or modify user details
  - Ability to reset passwords or adjust coin/xp balances manually
  - View and export user activity logs for troubleshooting

- **Security & Activity Logs:**  
  - A section for viewing IP addresses, login history, and account changes
  - Integration with audit logs so you can see if a user is doing anything unusual

---

### 3. **Test & Content Management**

- **Test Management:**  
  - A panel to add, edit, or delete tests  
  - A “test builder” interface that allows you to upload questions, options, explanations, and set scoring rules  
  - Preview tests as they would appear to users and check shuffling settings (both question order and answer choices)

- **Daily Content Management:**  
  - Manage the daily bonus settings (e.g. bonus amount, cooldown period)  
  - Manage the daily PBQ (question) pool, with the ability to add/edit/delete questions  
  - Set the “start time” or schedule for the daily question so it rotates at the same time for all users

---

### 4. **Security & Moderation Tools**

- **Suspicious Activity Dashboard:**  
  - Monitor abnormal behavior such as rapid bonus claims, multiple failed logins, or unusual coin transactions
  - Tools to flag or automatically suspend suspicious accounts

- **Audit Trail:**  
  - A detailed log of administrative actions (user deletions, test modifications, etc.)  
  - A database query log view (with read-only access) to help troubleshoot issues

- **Role-Based Access Control:**  
  - Implement different admin roles (super admin, moderator, support) with granular permissions
  - Enforce two-factor authentication (2FA) for admin logins

---

### 5. **Database & Performance Tools**

- **Embedded Database Shell (Read-Only):**  
  - Provide a secure, read-only interface to view collection contents (with search and filter features)  
  - Include index usage and query performance statistics

- **Performance Monitoring:**  
  - Integrate with a monitoring service (or build your own dashboard) to show real-time database metrics, such as average query time, connection counts, and error logs

- **API Health Checks:**  
  - Regularly run checks to verify that your critical endpoints (e.g. daily bonus, tests, user data) are performing well and not spamming unnecessarily

---

### 6. **Analytics & Reporting**

- **User & Test Analytics:**  
  - Reports on test engagement, bonus claim frequency, and retention metrics  
  - Visual charts showing trends (daily/weekly/monthly active users, coins awarded, test completion rates)

- **Export Capabilities:**  
  - Allow exporting of logs, user lists, and test statistics (CSV or Excel format) for offline analysis

---

### 7. **Integration with iOS & Global Considerations**

- **Unified Data:**  
  - Ensure that any changes made in the admin interface (like deleting a user, updating a test, or modifying bonus settings) immediately reflect across both your web and iOS apps.

- **Responsive Design:**  
  - Make sure the admin panel is responsive and works well on tablets or large smartphones (in case admins need to work on the go).

- **API Keys & Endpoints:**  
  - Provide a secure area for managing API keys that might be used by your mobile apps.

---

### Implementation Considerations

- **Backend API Routes:**  
  - Create routes for each of these functions. For example, routes to update user accounts, add/edit tests, view logs, and update bonus settings.
  - Secure these routes heavily (using tokens, 2FA, and IP whitelisting if necessary).

- **Frontend Framework:**  
  - Use a modern UI framework like React with a component library (e.g., Material-UI or Ant Design) to quickly build a professional-looking admin interface.
  - Implement proper state management (Redux or Context API) to manage the real-time updates (like bonus claim countdowns) across different views.

- **Database Considerations:**  
  - Ensure your database indexes are optimized for the queries used by the admin panel.
  - Consider implementing caching for heavy queries (e.g., analytics data) to improve responsiveness.

---

### Summary

Your admin interface should serve as a central control panel that allows you to:
- Monitor overall system health and user engagement.
- Manage users and content (tests, daily questions, bonus settings).
- Detect and respond to security issues.
- Access detailed performance metrics and audit logs.
- Provide seamless integration across your web and iOS apps.
- answer messages

This approach not only streamlines administrative tasks but also helps maintain a high level of security and performance for your application.

---

also you might need my mongosh command i use to go to my shell so her eit is 

mongosh "mongodb+srv://yoshi:Yoshi200369root@proxy.nmo0cjq.mongodb.net/xploitcraft?retryWrites=true&w=majority&appName=proxy"


so make sure to scan all my files and lets start with the backend models and routes

