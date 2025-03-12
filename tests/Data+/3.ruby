db.tests.insertOne({
  "category": "dataplus",
  "testId": 3,
  "testName": "CompTIA Data+ (DA0-001) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A data analyst is calculating the **average transaction amount per customer** over the past year. Which statistical measure should they use?",
      "options": [
        "Median",
        "Mode",
        "Mean",
        "Variance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Mean (average)** is calculated by summing all transaction amounts and dividing by the number of customers, making it the correct choice for determining the average transaction value.",
      "examTip": "Use **mean for averages**, median for middle values, and mode for most frequent values."
    },
    {
      "id": 2,
      "question": "A company needs to ensure that no two products in its database have the same SKU (Stock Keeping Unit). Which database constraint should be applied?",
      "options": [
        "Primary key",
        "Foreign key",
        "Check constraint",
        "Unique constraint"
      ],
      "correctAnswerIndex": 3,
      "explanation": "**A Unique constraint** ensures that no duplicate values exist in a specific column, making it the best choice for enforcing unique SKUs.",
      "examTip": "Use **Unique constraints for preventing duplicates**—Primary keys enforce uniqueness but also serve as row identifiers."
    },
    {
      "id": 3,
      "question": "A company needs to store **large volumes of structured and unstructured data** while allowing flexible schema modifications. Which type of database is BEST suited for this requirement?",
      "options": [
        "Relational database",
        "Document-based NoSQL database",
        "Columnar database",
        "Key-value store"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Document-based NoSQL databases** support flexible schemas, making them ideal for storing large volumes of structured and unstructured data.",
      "examTip": "Use **document-based NoSQL for flexible schema storage**—relational databases require predefined structures."
    },
    {
      "id": 4,
      "question": "A data engineer is designing a database schema for an **e-commerce platform**. Each order must be linked to a **valid customer ID** before being processed.\n\nWhich type of constraint should be applied to enforce this relationship?",
      "options": [
        "Primary key",
        "Foreign key",
        "Unique constraint",
        "Check constraint"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Foreign keys** enforce referential integrity by ensuring that each order references a valid customer record in the database.",
      "examTip": "Use **foreign keys to maintain relationships between tables**—Primary keys ensure row uniqueness."
    },
    {
      "id": 5,
      "question": "Match the **data storage type** on the left with its correct use case on the right.\n\n**Data Storage Type:**\nA. Relational Database\nB. Columnar Database\nC. Key-Value Store\nD. Data Lake\n\n**Use Case:**\n1. Storing structured data with predefined relationships\n2. High-speed retrieval of key-based data\n3. Fast analytical queries on large datasets\n4. Storing raw structured and unstructured data for future processing",
      "options": [
        "A → 1, B → 3, C → 2, D → 4",
        "A → 3, B → 2, C → 1, D → 4",
        "A → 2, B → 4, C → 3, D → 1",
        "A → 4, B → 1, C → 2, D → 3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Relational databases** store structured data, **columnar databases** optimize analytical queries, **key-value stores** support fast lookups, and **data lakes** store raw structured/unstructured data.",
      "examTip": "Understand **when to use relational vs. NoSQL vs. data lakes** for different business needs."
    },
    {
      "id": 6,
      "question": "A financial institution is conducting a **data governance audit** to verify that all employee access to sensitive customer records is properly controlled.\n\nWhich governance policy is the PRIMARY focus of this audit?",
      "options": [
        "Data masking policy",
        "Role-based access control",
        "Data retention policy",
        "Data lineage tracking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**RBAC (Role-Based Access Control)** ensures that employees only have access to data relevant to their roles, making it the focus of access control audits.",
      "examTip": "Use **RBAC for controlled access**—data masking hides sensitive fields but does not control access levels."
    },
    {
      "id": 7,
      "question": "A retail company is analyzing **customer purchasing behavior** to group similar customers based on spending habits.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Regression analysis",
        "Clustering analysis",
        "Hypothesis testing",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Clustering analysis** groups customers with similar spending behaviors, allowing businesses to create targeted marketing strategies.",
      "examTip": "Use **clustering for grouping similar data points**—regression is for predicting numerical relationships."
    },
    {
      "id": 8,
      "question": "A data engineer needs to **optimize query performance** for a large table where **queries frequently filter by order date**.\n\nWhich optimization strategy is MOST effective?",
      "options": [
        "Storing order records in a key-value NoSQL database",
        "Partitioning the table by order date",
        "Increasing database storage capacity",
        "Using a full table scan for every query"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Partitioning the table by order date** reduces query scan time by allowing the database to retrieve only relevant sections of the data.",
      "examTip": "Use **partitioning for large datasets with frequent date-based filtering**—indexes also help optimize queries."
    },
    {
      "id": 9,
      "question": "A company wants to analyze **customer satisfaction survey responses** to determine common complaints and sentiments. The dataset consists of free-text responses.\n\nWhich type of analysis is BEST suited for this task?",
      "options": [
        "Time series analysis",
        "Market basket analysis",
        "Natural language processing",
        "Regression analysis"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Natural language processing (NLP)** enables businesses to analyze textual feedback, extract themes, and assess customer sentiment.",
      "examTip": "Use **NLP for text-based analysis**—regression is used for numerical variable relationships."
    },
    {
      "id": 10,
      "question": "A retail company is analyzing **holiday sales trends** to forecast inventory needs for next year. The dataset contains daily sales data over five years.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Clustering analysis",
        "Hypothesis testing",
        "Time series analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Time series analysis** identifies patterns and seasonal trends over time, making it ideal for forecasting inventory needs.",
      "examTip": "Use **time series for trend forecasting**—clustering is used for grouping similar data."
    },
    {
      "id": 11,
      "question": "A business intelligence team needs to compare **quarterly sales revenue across different regions**.\n\nWhich type of chart is MOST appropriate?",
      "options": [
        "Pie chart",
        "Bar chart",
        "Line chart",
        "Heat map"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Bar charts** are ideal for comparing categorical data, such as sales across different regions.",
      "examTip": "Use **bar charts for categorical comparisons**, line charts for trends over time."
    },
    {
      "id": 12,
      "question": "A data engineer needs to **optimize query performance** in a database with millions of **customer transaction records**. The queries frequently filter by transaction date.\n\nWhich strategy is MOST effective?",
      "options": [
        "Creating an index on the transaction date column",
        "Using full table scans for every query",
        "Storing transaction records in a document-based NoSQL database",
        "Increasing storage space for the database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing the transaction date column** significantly improves query performance by allowing the database to quickly locate relevant records.",
      "examTip": "Use **indexes for frequently filtered fields**—full table scans slow down performance."
    },
    {
      "id": 13,
      "question": "A company needs to ensure that **no duplicate customer records** exist in its database. Which data cleaning method is BEST suited for this requirement?",
      "options": [
        "Data normalization",
        "Data deduplication",
        "Data aggregation",
        "Data parsing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data deduplication** removes redundant records, ensuring that customer information remains unique and accurate.",
      "examTip": "Use **deduplication for removing redundant records**—normalization organizes data efficiently."
    },
    {
      "id": 14,
      "question": "Match the **database optimization technique** on the left with its correct benefit on the right.\n\n**Database Optimization Technique:**\nA. Indexing\nB. Partitioning\nC. Caching\nD. Data Compression\n\n**Benefit:**\n1. Reduces query scan time by breaking large tables into smaller sections\n2. Improves retrieval speed by storing frequently accessed results in memory\n3. Reduces data storage requirements while maintaining accessibility\n4. Speeds up searches by creating structured references for frequently queried fields",
      "options": [
        "A → 4, B → 1, C → 2, D → 3",
        "A → 1, B → 3, C → 4, D → 2",
        "A → 3, B → 2, C → 1, D → 4",
        "A → 2, B → 4, C → 3, D → 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing speeds up searches, partitioning reduces scan time, caching improves access speed, and compression minimizes storage usage.**",
      "examTip": "Know **database optimization strategies** to improve query performance and storage efficiency."
    },
    {
      "id": 15,
      "question": "A company wants to ensure that **only authorized employees can access confidential financial data**.\n\nWhich security measure is MOST effective?",
      "options": [
        "Data encryption",
        "Role-based access control",
        "Data masking",
        "Data normalization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**RBAC (Role-Based Access Control)** restricts access to confidential financial data based on employee roles, ensuring only authorized users can view it.",
      "examTip": "Use **RBAC for access control**—encryption secures data but does not limit access."
    },
    {
      "id": 16,
      "question": "A company is implementing a **data retention policy** to comply with regulations requiring **customer records to be stored for five years**.\n\nWhich factor is MOST important when determining how long data should be retained?",
      "options": [
        "Database performance",
        "Storage costs",
        "Legal and compliance requirements",
        "User access frequency"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Legal and compliance requirements** dictate how long customer records must be stored, ensuring regulatory compliance.",
      "examTip": "Always align **data retention policies with legal requirements**—performance and storage costs are secondary."
    },
    {
      "id": 17,
      "question": "A data analyst is evaluating the **spread of sales revenue** across multiple store locations to determine how much sales values vary from the average.\n\nWhich statistical measure is MOST appropriate?",
      "options": [
        "Mean",
        "Mode",
        "Standard deviation",
        "Median"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Standard deviation** measures how much sales figures deviate from the average, making it the best choice for assessing variability.",
      "examTip": "Use **standard deviation for variability**—mean is for averages, and median is for middle values."
    },
    {
      "id": 18,
      "question": "A company needs to store **real-time website visitor data** and process it continuously for customer behavior analysis.\n\nWhich data processing method is MOST appropriate?",
      "options": [
        "Batch processing",
        "Stream processing",
        "ETL (Extract, Transform, Load)",
        "Data warehousing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Stream processing** allows for continuous real-time data ingestion and analysis, making it ideal for monitoring website visitor activity.",
      "examTip": "Use **stream processing for real-time analytics**—batch processing is better for scheduled data updates."
    },
    {
      "id": 19,
      "question": "A company needs to enforce **referential integrity** in a database to ensure that every order entry is linked to an existing customer.\n\nWhich database constraint is BEST suited for this requirement?",
      "options": [
        "Primary key",
        "Unique constraint",
        "Foreign key",
        "Check constraint"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Foreign keys** enforce referential integrity by ensuring that an order cannot exist without a corresponding customer record.",
      "examTip": "Use **foreign keys to maintain relationships between tables**—primary keys uniquely identify rows."
    },
    {
      "id": 20,
      "question": "Match the **data quality issue** on the left with its correct description on the right.\n\n**Data Quality Issue:**\nA. Data Redundancy\nB. Data Inconsistency\nC. Data Completeness\nD. Data Accuracy\n\n**Description:**\n1. Multiple copies of the same data stored unnecessarily\n2. Data values contradict across different systems\n3. Ensures all required data fields are present\n4. Ensures data correctly represents real-world values",
      "options": [
        "A → 1, B → 2, C → 3, D → 4",
        "A → 3, B → 1, C → 4, D → 2",
        "A → 2, B → 4, C → 1, D → 3",
        "A → 4, B → 3, C → 2, D → 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data redundancy** occurs when duplicate records exist, **data inconsistency** means conflicting values in different systems, **completeness** ensures no missing values, and **accuracy** checks real-world correctness.",
      "examTip": "Understand **common data quality issues** to improve dataset reliability."
    },
    {
      "id": 21,
      "question": "A company is migrating its **transaction records** to a new database system. To improve query speed, the database administrator decides to store frequently queried **customer order history** in memory.\n\nWhich optimization technique is being used?",
      "options": [
        "Partitioning",
        "Indexing",
        "Caching",
        "Normalization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Caching** stores frequently accessed data in memory, reducing the need for repeated database queries and improving performance.",
      "examTip": "Use **caching for fast access to frequently queried data**—indexing speeds up searches but doesn’t store results in memory."
    },
    {
      "id": 22,
      "question": "A company wants to ensure that **customer email addresses are always formatted correctly** before they are stored in a database.\n\nWhich database constraint is MOST appropriate?",
      "options": [
        "Foreign key",
        "Primary key",
        "Check constraint",
        "Unique constraint"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Check constraints** validate that data entered into a column follows a specific format, ensuring that email addresses are correctly structured.",
      "examTip": "Use **check constraints for enforcing data validation rules**—unique constraints prevent duplicate values."
    },
    {
      "id": 23,
      "question": "A data analyst is comparing **two different sales forecasting models** to determine which one provides more accurate predictions.\n\nWhich statistical method is MOST appropriate for this evaluation?",
      "options": [
        "Regression analysis",
        "Chi-squared test",
        "Mean absolute error (MAE)",
        "Time series analysis"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Mean absolute error (MAE)** measures the difference between predicted and actual values, making it useful for evaluating forecast accuracy.",
      "examTip": "Use **MAE for measuring prediction accuracy**—time series analysis identifies trends but does not compare model accuracy."
    },
    {
      "id": 24,
      "question": "A retail company wants to analyze **customer purchasing behavior across different regions** to identify spending patterns.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Trend analysis",
        "Clustering analysis",
        "Descriptive statistics",
        "Hypothesis testing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Clustering analysis** groups customers with similar spending behaviors, allowing businesses to identify distinct purchasing patterns by region.",
      "examTip": "Use **clustering for segmentation and pattern recognition**—trend analysis is for identifying changes over time."
    },
    {
      "id": 25,
      "question": "A company is analyzing customer purchase behavior to predict which customers are likely to make a **repeat purchase**.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Descriptive statistics",
        "Market basket analysis",
        "Predictive modeling",
        "Clustering analysis"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Predictive modeling** uses historical data to forecast future customer behaviors, making it the best choice for predicting repeat purchases.",
      "examTip": "Use **predictive modeling when forecasting future behavior**—descriptive statistics summarize past trends."
    },
    {
      "id": 26,
      "question": "A financial institution is implementing **data encryption** for all stored customer records. What is the PRIMARY purpose of encryption?",
      "options": [
        "To prevent unauthorized access by making data unreadable",
        "To improve query performance in a database",
        "To reduce redundancy in stored customer records",
        "To ensure data is always formatted correctly"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Encryption** ensures that data remains unreadable to unauthorized users, even if the database is compromised.",
      "examTip": "Use **encryption for securing stored and transmitted data**—it does not improve query performance."
    },
    {
      "id": 27,
      "question": "A company is reviewing its **data retention policies** to comply with regulatory requirements. What is the PRIMARY factor to consider when deciding how long to store customer data?",
      "options": [
        "Industry and legal requirements",
        "Database performance impact",
        "User access frequency",
        "Storage cost reduction"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Industry and legal requirements** dictate how long customer data must be retained to ensure regulatory compliance.",
      "examTip": "Always align **data retention policies with legal requirements**—performance and storage costs are secondary."
    },
    {
      "id": 28,
      "question": "A retail company is tracking **yearly sales performance** for multiple product categories. The company wants to easily compare revenue trends across categories.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Stacked bar chart",
        "Line chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Line charts** are ideal for comparing trends over time, making them the best choice for tracking yearly sales performance.",
      "examTip": "Use **line charts for time-based trends**—bar charts are better for categorical comparisons."
    },
    {
      "id": 29,
      "question": "Match the **data transformation technique** on the left with its correct purpose on the right.\n\n**Data Transformation Technique:**\nA. Data Parsing\nB. Data Imputation\nC. Data Aggregation\nD. Data Normalization\n\n**Purpose:**\n1. Extracts and converts structured data from unstructured text\n2. Summarizes large datasets into high-level metrics\n3. Fills in missing values using statistical methods\n4. Reduces redundancy by structuring data efficiently",
      "options": [
        "A → 1, B → 3, C → 2, D → 4",
        "A → 2, B → 4, C → 1, D → 3",
        "A → 3, B → 1, C → 4, D → 2",
        "A → 4, B → 2, C → 3, D → 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Parsing extracts structured data, imputation fills missing values, aggregation summarizes data, and normalization reduces redundancy.**",
      "examTip": "Understand **common transformation techniques** to prepare data for analysis."
    },
    {
      "id": 30,
      "question": "A business analyst wants to ensure that **customer data remains consistent** across multiple systems and reports.\n\nWhich data quality dimension is the PRIMARY focus?",
      "options": [
        "Data completeness",
        "Data consistency",
        "Data integrity",
        "Data accuracy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data consistency** ensures that the same values and formats are maintained across multiple systems, reducing discrepancies.",
      "examTip": "Use **data consistency checks** to prevent mismatched values across datasets."
    },
    {
      "id": 31,
      "question": "A data analyst is reviewing a dataset that contains **thousands of product reviews**. The goal is to identify **recurring themes and sentiments** in the text data.\n\nWhich technique is MOST appropriate?",
      "options": [
        "Time series analysis",
        "Natural language processing (NLP)",
        "Z-score analysis",
        "Market basket analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Natural language processing (NLP)** is used to analyze large amounts of text data, extract key themes, and perform sentiment analysis.",
      "examTip": "Use **NLP for analyzing text data**—time series analysis is better for numerical trends."
    },
    {
      "id": 32,
      "question": "A database administrator needs to improve **query speed** for a table containing millions of sales transactions. The queries frequently filter data based on **sales region**.\n\nWhich optimization strategy is MOST effective?",
      "options": [
        "Partitioning the table by sales region",
        "Removing unused indexes",
        "Using full table scans for every query",
        "Storing the table in a document-based NoSQL database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Partitioning the table by sales region** allows the database to retrieve only relevant sections of data, improving query efficiency.",
      "examTip": "Use **partitioning for large datasets with frequent region-based queries**—indexes also help optimize searches."
    },
    {
      "id": 33,
      "question": "A company needs to store **real-time sensor data** from IoT devices and process it continuously for analytics.\n\nWhich data storage solution is BEST suited for this requirement?",
      "options": [
        "Relational database",
        "Document-based NoSQL database",
        "Data warehouse",
        "Data lake"
      ],
      "correctAnswerIndex": 3,
      "explanation": "**Data lakes** support large volumes of structured and unstructured data, making them ideal for real-time IoT data ingestion and analytics.",
      "examTip": "Use **data lakes for flexible, large-scale data storage**—data warehouses enforce structured schema constraints."
    },
    {
      "id": 34,
      "question": "A data analyst needs to measure the **most frequently occurring product category** in a dataset containing retail transactions.\n\nWhich statistical measure should they use?",
      "options": [
        "Mean",
        "Median",
        "Mode",
        "Standard deviation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Mode** identifies the most frequently occurring value in a dataset, making it the best choice for analyzing the most common product category.",
      "examTip": "Use **mode for identifying the most frequently occurring values**—mean and median measure central tendencies."
    },
    {
      "id": 35,
      "question": "A database administrator is implementing **data partitioning** for a table containing millions of customer orders.\n\nWhat is the PRIMARY benefit of partitioning?",
      "options": [
        "Improves query performance by reducing the amount of scanned data",
        "Eliminates the need for indexes in large databases",
        "Ensures all data is stored in a single location for easy access",
        "Automatically removes duplicate records from the dataset"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Partitioning** divides large tables into smaller, more manageable pieces, reducing query scan time and improving retrieval performance.",
      "examTip": "Use **partitioning to optimize queries on large datasets**—indexes further enhance retrieval efficiency."
    },
    {
      "id": 36,
      "question": "A financial analyst wants to detect **suspicious transactions** by identifying **outliers** in a dataset of customer purchases.\n\nWhich statistical method is MOST appropriate?",
      "options": [
        "Regression analysis",
        "Z-score analysis",
        "Time series forecasting",
        "Market basket analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Z-score analysis** measures how far a data point deviates from the mean, making it useful for detecting outliers in financial transactions.",
      "examTip": "Use **Z-score for outlier detection**—regression is used for relationships between variables."
    },
    {
      "id": 37,
      "question": "Match the **data processing method** on the left with its correct description on the right.\n\n**Data Processing Method:**\nA. Batch Processing\nB. Stream Processing\nC. ETL (Extract, Transform, Load)\nD. ELT (Extract, Load, Transform)\n\n**Description:**\n1. Processes data continuously as it is received\n2. Applies transformations before loading into storage\n3. Loads raw data first, then applies transformations\n4. Processes data in scheduled intervals",
      "options": [
        "A → 4, B → 1, C → 2, D → 3",
        "A → 3, B → 4, C → 1, D → 2",
        "A → 2, B → 3, C → 4, D → 1",
        "A → 1, B → 2, C → 3, D → 4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Batch processing** handles data at scheduled intervals, **stream processing** processes data continuously, **ETL transforms before loading**, and **ELT loads data first before transforming.**",
      "examTip": "Use **batch processing for non-time-sensitive tasks** and **stream processing for real-time data flows.**"
    },
    {
      "id": 38,
      "question": "A company is conducting a **data quality audit** to identify **duplicate records and inconsistent formatting** in a customer database.\n\nWhich data quality dimension is the PRIMARY focus?",
      "options": [
        "Data integrity",
        "Data completeness",
        "Data consistency",
        "Data timeliness"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Data consistency** ensures that data is uniform across different systems and records, reducing duplication and format mismatches.",
      "examTip": "Use **data consistency checks** when ensuring that data remains standardized and accurate."
    },
    {
      "id": 39,
      "question": "A company wants to restrict **customer service agents** from viewing full credit card numbers in their customer service dashboard.\n\nWhich security technique is MOST appropriate?",
      "options": [
        "Data encryption",
        "Data masking",
        "Multi-factor authentication (MFA)",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data masking** hides sensitive information (such as credit card numbers) while allowing authorized users to access other customer details.",
      "examTip": "Use **data masking to protect sensitive information in reports and dashboards.**"
    },
    {
      "id": 40,
      "question": "A data engineer is optimizing a query that frequently **filters sales transactions by product category**.\n\nWhich optimization method is MOST effective?",
      "options": [
        "Creating an index on the product category column",
        "Partitioning the table by order date",
        "Storing product data in a key-value NoSQL database",
        "Increasing database storage capacity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing the product category column** allows the database to efficiently filter and retrieve relevant records, improving query performance.",
      "examTip": "Use **indexes to optimize queries on frequently searched fields**—partitioning helps for large datasets."
    },
    {
      "id": 41,
      "question": "A company wants to analyze customer purchase history to predict which products customers are most likely to buy next.\n\nWhich type of analysis is BEST suited for this requirement?",
      "options": [
        "Market basket analysis",
        "Time series analysis",
        "Descriptive statistics",
        "Hypothesis testing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Market basket analysis** helps identify patterns in purchasing behavior, allowing businesses to predict and recommend future purchases.",
      "examTip": "Use **market basket analysis for product recommendations**—time series is used for analyzing trends over time."
    },
    {
      "id": 42,
      "question": "A business intelligence team is designing a dashboard to visualize **quarterly revenue across different sales regions**. The goal is to compare performance across regions.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Bar chart",
        "Line chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Bar charts** are best for comparing categorical data, such as revenue across multiple regions.",
      "examTip": "Use **bar charts for comparing categories**—line charts are better for tracking changes over time."
    },
    {
      "id": 43,
      "question": "A database administrator is implementing **data deduplication** to ensure that customer records are unique.\n\nWhat is the PRIMARY benefit of data deduplication?",
      "options": [
        "Reduces storage costs by eliminating duplicate records",
        "Improves database performance by increasing indexing speed",
        "Enhances data security by encrypting sensitive information",
        "Enforces referential integrity in relational databases"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data deduplication** removes redundant records, reducing storage costs and improving data integrity.",
      "examTip": "Use **data deduplication to remove redundant records**—it does not enforce referential integrity."
    },
    {
      "id": 44,
      "question": "Match the **data governance concept** on the left with its correct description on the right.\n\n**Data Governance Concept:**\nA. Data Retention Policy\nB. Data Stewardship\nC. Data Classification\nD. Data Quality Metrics\n\n**Description:**\n1. Defines how long data should be stored before deletion\n2. Oversees compliance and best practices in data management\n3. Categorizes data based on sensitivity and security requirements\n4. Measures accuracy, consistency, and completeness of data",
      "options": [
        "A → 1, B → 2, C → 3, D → 4",
        "A → 3, B → 1, C → 4, D → 2",
        "A → 2, B → 4, C → 1, D → 3",
        "A → 4, B → 3, C → 2, D → 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data retention policies** define storage durations, **stewardship** ensures compliance, **classification** assigns sensitivity levels, and **quality metrics** measure data accuracy.",
      "examTip": "Understand **key data governance principles** for security and compliance."
    },
    {
      "id": 45,
      "question": "A financial institution is applying **data masking** to credit card numbers displayed in customer service dashboards.\n\nWhat is the PRIMARY purpose of data masking?",
      "options": [
        "To encrypt stored credit card numbers",
        "To restrict access to customer data",
        "To hide sensitive data while maintaining usability",
        "To improve query performance in databases"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Data masking** hides sensitive information (e.g., credit card numbers) while still allowing customer service agents to perform their tasks.",
      "examTip": "Use **data masking for controlled visibility**—encryption secures stored data."
    },
    {
      "id": 46,
      "question": "A company is optimizing its **data warehouse queries**. The database administrator decides to store **precomputed summaries** of frequently used reports to improve performance.\n\nWhich technique is being used?",
      "options": [
        "Partitioning",
        "Indexing",
        "Materialized views",
        "Data compression"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Materialized views** store precomputed query results, reducing the need for expensive recalculations and improving query speed.",
      "examTip": "Use **materialized views for performance optimization in data warehouses**—indexes help with retrieval but do not store precomputed results."
    },
    {
      "id": 47,
      "question": "A company wants to analyze **daily website traffic** to detect sudden spikes in visitor activity. Which analysis technique is MOST appropriate?",
      "options": [
        "Z-score analysis",
        "Time series analysis",
        "Market basket analysis",
        "Regression analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Time series analysis** identifies patterns and anomalies over time, making it ideal for detecting spikes in website traffic.",
      "examTip": "Use **time series for analyzing patterns over time**—Z-score analysis is better for detecting outliers."
    },
    {
      "id": 48,
      "question": "A company is transitioning from an **ETL (Extract, Transform, Load)** process to an **ELT (Extract, Load, Transform)** approach using cloud storage.\n\nWhat is the PRIMARY advantage of ELT over ETL?",
      "options": [
        "Transforms data before loading, reducing storage costs",
        "Allows raw data to be stored immediately for flexible analysis",
        "Minimizes the need for indexing in cloud databases",
        "Ensures data deduplication occurs before storage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**ELT loads raw data first**, allowing for flexible transformations later, making it ideal for cloud-based big data processing.",
      "examTip": "Use **ELT when transformation flexibility is needed**—ETL is better for structured environments."
    },
    {
      "id": 49,
      "question": "A company is storing **daily transaction records** and needs to ensure that **all transactions are processed in real-time**.\n\nWhich data processing method is BEST suited for this requirement?",
      "options": [
        "Batch processing",
        "Stream processing",
        "Data warehousing",
        "ETL (Extract, Transform, Load)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Stream processing** enables continuous, real-time transaction processing, making it ideal for businesses that require immediate data updates.",
      "examTip": "Use **stream processing for real-time data ingestion**—batch processing handles data in scheduled intervals."
    },
    {
      "id": 50,
      "question": "A database administrator needs to enforce **referential integrity** between the 'Orders' table and the 'Customers' table.\n\nWhich database constraint is MOST appropriate?",
      "options": [
        "Primary key",
        "Foreign key",
        "Unique constraint",
        "Check constraint"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Foreign keys** ensure that an order cannot exist without a corresponding customer record, enforcing referential integrity.",
      "examTip": "Use **foreign keys to maintain relationships between tables**—primary keys uniquely identify records."
    },
    {
      "id": 51,
      "question": "A company wants to analyze **historical customer behavior data** to predict which customers are likely to make a purchase in the next month.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Regression analysis",
        "Predictive modeling",
        "Clustering analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Predictive modeling** uses historical data to forecast future customer behaviors, making it ideal for predicting future purchases.",
      "examTip": "Use **predictive modeling for forecasting customer behavior**—clustering groups similar customers."
    },
    {
      "id": 52,
      "question": "A data engineer needs to improve query performance for a **large database table** where queries frequently filter by order date.\n\nWhich optimization technique is MOST effective?",
      "options": [
        "Partitioning the table by order date",
        "Removing indexes to reduce storage space",
        "Using full table scans for every query",
        "Increasing database memory allocation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Partitioning the table by order date** allows the database to efficiently retrieve relevant records, improving query performance.",
      "examTip": "Use **partitioning for large tables with predictable filtering conditions**—indexes also improve performance."
    },
    {
      "id": 53,
      "question": "Match the **data quality dimension** on the left with its correct description on the right.\n\n**Data Quality Dimension:**\nA. Data Accuracy\nB. Data Completeness\nC. Data Consistency\nD. Data Integrity\n\n**Description:**\n1. Ensures that all required data is present\n2. Ensures that data values are correct and reliable\n3. Ensures that data remains uniform across different sources\n4. Maintains logical relationships between datasets to prevent corruption",
      "options": [
        "A → 2, B → 1, C → 3, D → 4",
        "A → 1, B → 3, C → 2, D → 4",
        "A → 3, B → 4, C → 1, D → 2",
        "A → 4, B → 2, C → 1, D → 3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data accuracy** ensures reliability, **completeness** checks for missing values, **consistency** ensures uniformity, and **integrity** maintains relationships.",
      "examTip": "Understand **data quality dimensions** to maintain high-quality datasets."
    },
    {
      "id": 54,
      "question": "A company is implementing a **data encryption policy** to protect sensitive customer records.\n\nWhat is the PRIMARY purpose of encryption?",
      "options": [
        "To improve query performance by compressing data",
        "To ensure only authorized users can access the data",
        "To remove duplicate records from a database",
        "To standardize data formats before storage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Encryption** secures sensitive data by making it unreadable to unauthorized users, protecting against data breaches.",
      "examTip": "Use **encryption to secure stored and transmitted data**—it does not improve query performance."
    },
    {
      "id": 55,
      "question": "A retail company wants to analyze **weekly revenue trends** across multiple store locations.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Line chart",
        "Stacked bar chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Line charts** are best for tracking trends over time, making them the best choice for analyzing weekly revenue trends.",
      "examTip": "Use **line charts for time-series data**—bar charts compare categorical values."
    },
    {
      "id": 56,
      "question": "A company is transitioning from a **traditional data warehouse** to a **data lake**. What is the PRIMARY benefit of using a data lake?",
      "options": [
        "It enforces strict data schemas before data is stored",
        "It allows raw, structured, and unstructured data to be stored for future processing",
        "It provides faster query performance for transactional processing",
        "It reduces the need for data backups"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data lakes** store raw, structured, and unstructured data, providing flexibility for future analysis and big data applications.",
      "examTip": "Use **data lakes for flexible storage**—data warehouses enforce strict schemas for structured data."
    },
    {
      "id": 57,
      "question": "A business analyst is comparing **two different sales forecasting models** to determine which one provides more accurate predictions.\n\nWhich statistical method is MOST appropriate for this evaluation?",
      "options": [
        "Regression analysis",
        "Mean absolute error (MAE)",
        "Chi-squared test",
        "Time series analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Mean absolute error (MAE)** measures the difference between predicted and actual values, making it useful for evaluating forecast accuracy.",
      "examTip": "Use **MAE for measuring prediction accuracy**—time series analysis identifies trends but does not compare model accuracy."
    },
    {
      "id": 58,
      "question": "A database administrator needs to improve **query performance** for a table containing millions of customer orders. The queries frequently filter data based on **order date**.\n\nWhich optimization strategy is MOST effective?",
      "options": [
        "Creating an index on the order date column",
        "Partitioning the table by customer ID",
        "Removing indexes to reduce storage size",
        "Using full table scans for every query"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Creating an index on the order date column** allows the database to retrieve data efficiently, improving query performance.",
      "examTip": "Use **indexes for optimizing searches on frequently queried fields**—partitioning helps for large datasets with predictable queries."
    },
    {
      "id": 59,
      "question": "A company wants to analyze **customer purchase trends** to determine if a **relationship exists between product price and total sales volume**.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Market basket analysis",
        "Clustering analysis",
        "Correlation analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Correlation analysis** measures the relationship between two numerical variables, making it ideal for analyzing price and sales volume.",
      "examTip": "Use **correlation analysis for numerical relationships**—market basket analysis identifies frequently bought products together."
    },
    {
      "id": 60,
      "question": "A company is conducting a **data governance audit** to verify that employee access to sensitive customer records is properly restricted.\n\nWhich governance policy is the PRIMARY focus of this audit?",
      "options": [
        "Data masking policy",
        "Role-based access control (RBAC)",
        "Data retention policy",
        "Data lineage tracking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**RBAC (Role-Based Access Control)** ensures that employees only have access to data relevant to their roles, making it the focus of access control audits.",
      "examTip": "Use **RBAC to enforce controlled access**—data masking hides sensitive fields but does not control access."
    },
    {
      "id": 61,
      "question": "A retail company wants to analyze **customer demographics** to understand **which age groups purchase certain product categories**.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Histogram",
        "Line chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Histograms** are best for visualizing the distribution of numerical data (e.g., age groups) across categories.",
      "examTip": "Use **histograms for visualizing numerical data distributions**—bar charts compare categorical data."
    },
    {
      "id": 62,
      "question": "Match the **database concept** on the left with its correct description on the right.\n\n**Database Concept:**\nA. Indexing\nB. Partitioning\nC. Normalization\nD. Foreign Key\n\n**Description:**\n1. Reduces redundancy by structuring data into related tables\n2. Links records between related tables to enforce referential integrity\n3. Divides large tables into smaller segments to improve performance\n4. Improves query performance by optimizing data retrieval",
      "options": [
        "A → 4, B → 3, C → 1, D → 2",
        "A → 3, B → 4, C → 2, D → 1",
        "A → 1, B → 2, C → 3, D → 4",
        "A → 2, B → 1, C → 4, D → 3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing improves retrieval speed, partitioning divides large tables, normalization reduces redundancy, and foreign keys maintain relationships.**",
      "examTip": "Understand **key database concepts** to optimize storage and performance."
    },
    {
      "id": 63,
      "question": "A company wants to ensure that **customer data remains consistent** across multiple systems and reports.\n\nWhich data quality dimension is the PRIMARY focus?",
      "options": [
        "Data completeness",
        "Data consistency",
        "Data accuracy",
        "Data timeliness"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data consistency** ensures that data is uniform across different systems and reports, reducing discrepancies.",
      "examTip": "Use **data consistency checks** to prevent mismatched values across datasets."
    },
    {
      "id": 64,
      "question": "A data engineer needs to process **large volumes of raw data** from multiple sources and store it for future analysis. The company wants a flexible storage solution that does not require predefined schemas.\n\nWhich data storage solution is MOST appropriate?",
      "options": [
        "Relational database",
        "Document-based NoSQL database",
        "Data lake",
        "Columnar database"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Data lakes** allow flexible storage of raw, structured, and unstructured data, making them ideal for big data environments.",
      "examTip": "Use **data lakes for storing diverse data types**—relational databases enforce predefined schemas."
    },
    {
      "id": 65,
      "question": "A data analyst needs to measure the **degree of variation in sales revenue** across multiple store locations. Which statistical measure is MOST appropriate?",
      "options": [
        "Mean",
        "Standard deviation",
        "Mode",
        "Median"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Standard deviation** measures how much individual sales values deviate from the average, making it the best choice for analyzing variability across locations.",
      "examTip": "Use **standard deviation for variability**—mean is for averages, and mode is for most common values."
    },
    {
      "id": 66,
      "question": "A company wants to store **semi-structured customer support logs** that contain text, timestamps, and metadata while allowing flexible querying.\n\nWhich type of database is BEST suited for this requirement?",
      "options": [
        "Relational database",
        "Document-based NoSQL database",
        "Columnar database",
        "Key-value store"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Document-based NoSQL databases** store semi-structured data efficiently while allowing flexible queries.",
      "examTip": "Use **document-based NoSQL for semi-structured data with flexible schemas**—relational databases require predefined structures."
    },
    {
      "id": 67,
      "question": "A data engineer is tasked with improving the efficiency of an **SQL query that filters transaction records by transaction date**. What is the BEST optimization technique?",
      "options": [
        "Creating an index on the transaction date column",
        "Partitioning the database by customer ID",
        "Removing indexes to reduce storage space",
        "Using full table scans for all queries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing the transaction date column** allows the database to retrieve relevant records quickly, improving query performance.",
      "examTip": "Use **indexes for frequently searched fields**—partitioning is useful for large datasets with predictable filtering."
    },
    {
      "id": 68,
      "question": "A company is analyzing product sales trends over the last **five years** to identify seasonal patterns. Which type of analysis is MOST appropriate?",
      "options": [
        "Regression analysis",
        "Time series analysis",
        "Clustering analysis",
        "Market basket analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Time series analysis** identifies patterns over time, making it ideal for detecting seasonal trends in product sales.",
      "examTip": "Use **time series for analyzing trends over time**—clustering is used for grouping data points."
    },
    {
      "id": 69,
      "question": "A company is conducting a **data quality audit** to identify missing customer records and incorrect data entries. Which data quality dimension is the PRIMARY focus?",
      "options": [
        "Data accuracy",
        "Data completeness",
        "Data consistency",
        "Data timeliness"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data completeness** ensures that all required records and values are present, making it the main focus when identifying missing data.",
      "examTip": "Use **data completeness checks** to ensure all necessary records and fields are available."
    },
    {
      "id": 70,
      "question": "Match the **data security technique** on the left with its correct function on the right.\n\n**Data Security Technique:**\nA. Data Encryption\nB. Data Masking\nC. Multi-Factor Authentication (MFA)\nD. Role-Based Access Control (RBAC)\n\n**Function:**\n1. Requires users to verify their identity through multiple steps\n2. Hides sensitive data in reports while keeping it usable\n3. Converts data into unreadable format to prevent unauthorized access\n4. Restricts data access based on user roles",
      "options": [
        "A → 3, B → 2, C → 1, D → 4",
        "A → 2, B → 4, C → 1, D → 3",
        "A → 1, B → 3, C → 4, D → 2",
        "A → 4, B → 1, C → 3, D → 2"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Encryption secures data, masking hides data in reports, MFA adds authentication layers, and RBAC restricts access by roles.**",
      "examTip": "Understand **when to use encryption vs. masking vs. RBAC vs. MFA** for data security."
    },
    {
      "id": 71,
      "question": "A retail company is comparing **quarterly sales revenue across multiple store locations**. Which visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Stacked bar chart",
        "Line chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Stacked bar charts** effectively display sales comparisons across multiple categories, such as store locations.",
      "examTip": "Use **stacked bar charts for category comparisons over time**—line charts are better for tracking trends."
    },
    {
      "id": 72,
      "question": "A company is transitioning from a **traditional data warehouse** to a **cloud-based data lake**. What is the PRIMARY advantage of a data lake?",
      "options": [
        "It enforces strict data schemas before storage",
        "It allows raw, structured, and unstructured data to be stored for future processing",
        "It provides faster query performance for transactional processing",
        "It reduces the need for data backups"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data lakes** allow for flexible storage of raw, structured, and unstructured data, making them ideal for big data environments.",
      "examTip": "Use **data lakes for flexible, large-scale data storage**—data warehouses enforce predefined schemas for structured data."
    },
    {
      "id": 73,
      "question": "A retail company wants to analyze **weekly revenue trends** across different store locations. The dataset contains daily sales amounts for each store.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Line chart",
        "Stacked bar chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Line charts** are best for tracking trends over time, making them ideal for analyzing weekly revenue trends across stores.",
      "examTip": "Use **line charts for time-series data**—bar charts compare categorical values."
    },
    {
      "id": 74,
      "question": "A company is analyzing **customer support call logs** to identify the most frequent types of customer complaints.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Time series analysis",
        "Natural language processing (NLP)",
        "Regression analysis",
        "Market basket analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Natural language processing (NLP)** enables businesses to analyze textual customer feedback and extract key themes or sentiments.",
      "examTip": "Use **NLP for analyzing text data**—time series analysis is better for numerical trends."
    },
    {
      "id": 75,
      "question": "A business intelligence team is designing a dashboard to compare **quarterly sales revenue across different sales regions**. The goal is to display sales performance for multiple regions side by side.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Bar chart",
        "Line chart",
        "Heat map"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Bar charts** are best for comparing categorical data, such as sales revenue across multiple regions.",
      "examTip": "Use **bar charts for category comparisons**—line charts are better for tracking trends over time."
    },
    {
      "id": 76,
      "question": "Match the **data transformation technique** on the left with its correct purpose on the right.\n\n**Data Transformation Technique:**\nA. Data Imputation\nB. Data Aggregation\nC. Data Normalization\nD. Data Parsing\n\n**Purpose:**\n1. Extracts structured values from unstructured text\n2. Summarizes data to generate high-level metrics\n3. Reduces redundancy by structuring data efficiently\n4. Fills in missing values using statistical methods",
      "options": [
        "A → 4, B → 2, C → 3, D → 1",
        "A → 3, B → 1, C → 4, D → 2",
        "A → 2, B → 4, C → 1, D → 3",
        "A → 1, B → 3, C → 2, D → 4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Imputation** fills missing values, **aggregation** summarizes data, **normalization** structures data efficiently, and **parsing** extracts structured values from text.",
      "examTip": "Understand **key transformation techniques** to improve data quality and analysis."
    },
    {
      "id": 77,
      "question": "A company wants to ensure that **sensitive customer information is not displayed in full on reports but remains available for processing**.\n\nWhich security method is MOST appropriate?",
      "options": [
        "Data encryption",
        "Data masking",
        "Role-based access control (RBAC)",
        "Data deduplication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data masking** hides sensitive values while keeping data usable for reporting and analysis.",
      "examTip": "Use **data masking for controlled visibility**—encryption secures stored data but does not obscure displayed values."
    },
    {
      "id": 78,
      "question": "A company wants to improve **query performance** in a large customer database. Queries frequently filter by customer ID.\n\nWhich database optimization technique is MOST effective?",
      "options": [
        "Creating an index on the customer ID column",
        "Storing customer records in a document-based NoSQL database",
        "Removing indexes to reduce storage space",
        "Using full table scans for all queries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing the customer ID column** allows the database to quickly retrieve relevant records, improving query performance.",
      "examTip": "Use **indexes to optimize searches on frequently queried fields**—removing indexes slows down queries."
    },
    {
      "id": 79,
      "question": "A data analyst is reviewing a dataset containing **customer transaction records**. The analyst needs to identify **which products are frequently purchased together**.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Market basket analysis",
        "Regression analysis",
        "Clustering analysis",
        "Z-score analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Market basket analysis** identifies relationships between frequently purchased products, making it useful for cross-selling strategies.",
      "examTip": "Use **market basket analysis for product recommendation strategies**—clustering is for grouping similar data points."
    },
    {
      "id": 80,
      "question": "A company is transitioning from an **ETL (Extract, Transform, Load) process** to an **ELT (Extract, Load, Transform) approach**. What is the PRIMARY advantage of using ELT?",
      "options": [
        "Transforms data before loading, reducing storage costs",
        "Loads raw data first, allowing for flexible transformation later",
        "Minimizes the need for indexing in databases",
        "Ensures data deduplication occurs before storage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**ELT loads raw data first**, allowing flexible transformations later, making it ideal for cloud-based big data environments.",
      "examTip": "Use **ELT when transformation flexibility is needed**—ETL is better for structured environments."
    },
    {
      "id": 81,
      "question": "A retail company is analyzing **customer purchase trends** to determine if a relationship exists between product price and total sales volume.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Market basket analysis",
        "Clustering analysis",
        "Correlation analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Correlation analysis** measures the relationship between two numerical variables, making it ideal for analyzing price and sales volume.",
      "examTip": "Use **correlation analysis for numerical relationships**—market basket analysis identifies frequently bought products together."
    },
    {
      "id": 82,
      "question": "A company needs to ensure that **sensitive customer data is not displayed in full on reports but remains accessible for processing**.\n\nWhich security method is MOST appropriate?",
      "options": [
        "Data encryption",
        "Data masking",
        "Role-based access control (RBAC)",
        "Data deduplication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data masking** hides sensitive values while keeping data usable for reporting and analysis.",
      "examTip": "Use **data masking for controlled visibility**—encryption secures stored data but does not obscure displayed values."
    },
    {
      "id": 83,
      "question": "A company is implementing a **data retention policy** to comply with industry regulations. What is the PRIMARY factor to consider when determining how long data should be stored?",
      "options": [
        "Database performance",
        "Industry and legal requirements",
        "User access frequency",
        "Storage cost reduction"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Industry and legal requirements** dictate how long customer data must be retained to ensure regulatory compliance.",
      "examTip": "Always align **data retention policies with legal requirements**—performance and storage costs are secondary."
    },
    {
      "id": 84,
      "question": "A financial analyst wants to detect **suspicious transactions** by identifying **outliers** in a dataset of customer purchases.\n\nWhich statistical method is MOST appropriate?",
      "options": [
        "Regression analysis",
        "Z-score analysis",
        "Time series forecasting",
        "Market basket analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Z-score analysis** measures how far a data point deviates from the mean, making it useful for detecting outliers in financial transactions.",
      "examTip": "Use **Z-score for outlier detection**—regression is used for relationships between variables."
    },
    {
      "id": 85,
      "question": "A business intelligence team is designing a dashboard to compare **monthly sales performance across multiple product categories**.\n\nWhich visualization type is MOST appropriate?",
      "options": [
        "Pie chart",
        "Stacked bar chart",
        "Line chart",
        "Scatter plot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Stacked bar charts** effectively display sales comparisons across multiple categories.",
      "examTip": "Use **stacked bar charts for category comparisons over time**—line charts are better for tracking trends."
    },
    {
      "id": 86,
      "question": "Match the **database optimization technique** on the left with its correct benefit on the right.\n\n**Database Optimization Technique:**\nA. Indexing\nB. Partitioning\nC. Caching\nD. Data Compression\n\n**Benefit:**\n1. Reduces query scan time by breaking large tables into smaller sections\n2. Improves retrieval speed by storing frequently accessed results in memory\n3. Reduces data storage requirements while maintaining accessibility\n4. Speeds up searches by creating structured references for frequently queried fields",
      "options": [
        "A → 4, B → 1, C → 2, D → 3",
        "A → 1, B → 3, C → 4, D → 2",
        "A → 3, B → 2, C → 1, D → 4",
        "A → 2, B → 4, C → 3, D → 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Indexing speeds up searches, partitioning reduces scan time, caching improves access speed, and compression minimizes storage usage.**",
      "examTip": "Know **database optimization strategies** to improve query performance and storage efficiency."
    },
    {
      "id": 87,
      "question": "A database administrator is implementing **data deduplication** to ensure that customer records are unique.\n\nWhat is the PRIMARY benefit of data deduplication?",
      "options": [
        "Reduces storage costs by eliminating duplicate records",
        "Improves database performance by increasing indexing speed",
        "Enhances data security by encrypting sensitive information",
        "Enforces referential integrity in relational databases"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data deduplication** removes redundant records, reducing storage costs and improving data integrity.",
      "examTip": "Use **data deduplication to remove redundant records**—it does not enforce referential integrity."
    },
    {
      "id": 88,
      "question": "A company is transitioning from a **traditional data warehouse** to a **cloud-based data lake**. What is the PRIMARY benefit of using a data lake?",
      "options": [
        "It enforces strict data schemas before storage",
        "It allows raw, structured, and unstructured data to be stored for future processing",
        "It provides faster query performance for transactional processing",
        "It reduces the need for data backups"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data lakes** allow for flexible storage of raw, structured, and unstructured data, making them ideal for big data environments.",
      "examTip": "Use **data lakes for flexible, large-scale data storage**—data warehouses enforce predefined schemas for structured data."
    },
    {
      "id": 89,
      "question": "A company is implementing **role-based access control (RBAC)** to protect financial data. What is the PRIMARY purpose of RBAC?",
      "options": [
        "To encrypt sensitive data before storage",
        "To restrict user access based on job roles",
        "To mask customer data in reports",
        "To improve query performance for financial records"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**RBAC (Role-Based Access Control)** ensures that employees can only access the data required for their job functions, improving security and compliance.",
      "examTip": "Use **RBAC to control data access based on user roles**—encryption secures data but does not limit visibility."
    },
    {
      "id": 90,
      "question": "A business analyst wants to determine whether a new **customer loyalty program** has significantly increased repeat purchases. The dataset includes customer purchase history before and after the program launch.\n\nWhich statistical method is MOST appropriate?",
      "options": [
        "Chi-squared test",
        "T-test",
        "Regression analysis",
        "Z-score analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**T-tests** compare the means of two independent groups, making them the best choice for determining whether the loyalty program increased repeat purchases.",
      "examTip": "Use **T-tests for comparing means of two groups**—Chi-squared tests are for categorical relationships."
    },
    {
      "id": 91,
      "question": "A company wants to **identify trends in product demand over the past five years**. The dataset includes sales records with timestamps.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Market basket analysis",
        "Clustering analysis",
        "Time series analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Time series analysis** helps identify long-term trends and seasonal variations in sales data, making it ideal for analyzing product demand over time.",
      "examTip": "Use **time series for analyzing trends over time**—clustering groups similar data points."
    },
    {
      "id": 92,
      "question": "A database administrator is optimizing a **large customer database**. The queries frequently filter data by **customer region**.\n\nWhich optimization strategy is MOST effective?",
      "options": [
        "Partitioning the table by customer region",
        "Removing indexes to reduce storage space",
        "Using full table scans for all queries",
        "Storing the table in a document-based NoSQL database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Partitioning the table by customer region** improves query performance by allowing the database to retrieve only relevant sections of data.",
      "examTip": "Use **partitioning for large datasets with frequent region-based queries**—indexes also help optimize searches."
    },
    {
      "id": 93,
      "question": "Match the **data security technique** on the left with its correct function on the right.\n\n**Data Security Technique:**\nA. Data Encryption\nB. Data Masking\nC. Multi-Factor Authentication (MFA)\nD. Access Control Lists (ACLs)\n\n**Function:**\n1. Hides sensitive data in reports while keeping it usable\n2. Protects data by converting it into unreadable format\n3. Requires users to verify their identity through multiple steps\n4. Controls which users can access specific data or files",
      "options": [
        "A → 2, B → 1, C → 3, D → 4",
        "A → 3, B → 4, C → 1, D → 2",
        "A → 1, B → 3, C → 4, D → 2",
        "A → 4, B → 2, C → 1, D → 3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Encryption secures data, masking hides data in reports, MFA adds authentication layers, and ACLs control data access.**",
      "examTip": "Understand **when to use encryption, masking, MFA, and ACLs** for security."
    },
    {
      "id": 94,
      "question": "A company wants to analyze **customer behavior across different demographic groups** to identify **which products are most popular among each group**.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Descriptive statistics",
        "Clustering analysis",
        "Market basket analysis",
        "Time series analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Clustering analysis** groups customers with similar purchasing behaviors, allowing businesses to identify distinct buying patterns across demographics.",
      "examTip": "Use **clustering for segmentation and pattern recognition**—market basket analysis focuses on product pairings."
    },
    {
      "id": 95,
      "question": "A company is transitioning from a **traditional ETL (Extract, Transform, Load) process** to an **ELT (Extract, Load, Transform) approach**. What is the PRIMARY advantage of ELT?",
      "options": [
        "Transforms data before loading, reducing storage costs",
        "Loads raw data first, allowing for flexible transformation later",
        "Minimizes the need for indexing in cloud databases",
        "Ensures data deduplication occurs before storage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**ELT loads raw data first**, allowing flexible transformations later, making it ideal for cloud-based big data environments.",
      "examTip": "Use **ELT when transformation flexibility is needed**—ETL is better for structured environments."
    },
    {
      "id": 96,
      "question": "A company is conducting a **data audit** to identify missing customer records and incorrect data entries. Which data quality dimension is the PRIMARY focus?",
      "options": [
        "Data completeness",
        "Data consistency",
        "Data accuracy",
        "Data timeliness"
      ],
      "correctAnswerIndex": 0,
      "explanation": "**Data completeness** ensures that all required records and values are present, making it the main focus when identifying missing data.",
      "examTip": "Use **data completeness checks** to ensure all necessary records and fields are available."
    },
    {
      "id": 97,
      "question": "A company is implementing **data encryption** to protect customer records stored in a database. What is the PRIMARY benefit of encrypting stored data?",
      "options": [
        "It prevents data duplication within the database.",
        "It ensures that only authorized users can modify data.",
        "It makes the data unreadable to unauthorized users.",
        "It improves query performance for large datasets."
      ],
      "correctAnswerIndex": 2,
      "explanation": "**Data encryption** ensures that sensitive data remains unreadable to unauthorized users, even if the database is compromised.",
      "examTip": "Use **encryption for data security**—access controls limit modifications, but encryption protects against breaches."
    },
    {
      "id": 98,
      "question": "A data engineer is designing a **query that frequently filters records based on customer ID**. What is the BEST strategy to improve query performance?",
      "options": [
        "Partitioning the database by customer ID",
        "Creating an index on the customer ID column",
        "Storing customer data in a separate database",
        "Using full table scans for every query"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Indexing the customer ID column** speeds up queries by allowing the database to quickly locate relevant records without scanning the entire table.",
      "examTip": "Use **indexes for frequently searched fields**—partitioning is useful for large datasets with predictable filtering."
    },
    {
      "id": 99,
      "question": "A business intelligence team wants to analyze **customer feedback data** collected from surveys. The dataset consists of text responses.\n\nWhich type of analysis is MOST appropriate?",
      "options": [
        "Time series analysis",
        "Natural language processing (NLP)",
        "Regression analysis",
        "Descriptive statistics"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Natural language processing (NLP)** is used to analyze and extract insights from text data, making it ideal for customer feedback analysis.",
      "examTip": "Use **NLP for text-based analysis**—descriptive statistics work better for numerical data."
    },
    {
      "id": 100,
      "question": "A company is conducting a **data quality audit** to ensure accurate reporting. The audit focuses on identifying **duplicate records, missing values, and inconsistent formatting**.\n\nWhich data quality dimension is the PRIMARY focus?",
      "options": [
        "Data consistency",
        "Data completeness",
        "Data accuracy",
        "Data timeliness"
      ],
      "correctAnswerIndex": 1,
      "explanation": "**Data completeness** ensures that all required data fields are filled and correct, making it the key focus when addressing duplicates, missing values, and formatting issues.",
      "examTip": "Use **data completeness checks** when ensuring all necessary records and fields are available."
    }
  ]
});
