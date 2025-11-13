# ☁️ Personalized Cloud Log Risk Categorizer using AWS CloudTrail

A Python-based tool that analyzes AWS CloudTrail logs and categorizes cloud events into **Low**, **Medium**, or **High** risk levels using custom logic.  
This project is designed for **students, researchers, and cloud security learners** who want actionable insights from AWS logs without needing complex infrastructure setups.

---

## 📌 Problem Statement

In cloud environments like AWS, thousands of log entries are generated daily through CloudTrail.  
Due to the sheer volume and complexity, **critical security events often go unnoticed**.  

This tool simplifies cloud log analysis by:
- Parsing AWS CloudTrail logs automatically.
- Identifying and classifying potential risks.
- Providing better visibility into user activity and anomalies.

---

## 🎯 Objectives

- Automate log inspection and categorization to reduce manual analysis time.  
- Enhance **cloud security visibility** by detecting high-risk or unusual operations.  
- Enable **customizable risk rules** to adapt to different security policies.  
- Present results in a **structured and readable format** for security reporting.

---

## 🚀 Features

✅ **Automated Log Analysis** – Parses CloudTrail JSON logs and classifies risks.  
✅ **Customizable Rules** – Modify predefined security rules to suit your environment.  
✅ **Multi-Risk Categorization** – Classifies logs as *Low*, *Medium*, or *High* risk.  
✅ **Lightweight & Portable** – Requires only Python and CloudTrail log files.  
✅ **Extensible Design** – Can integrate with AWS SDK (Boto3) or dashboards later.  
✅ **Open Source & Educational** – Ideal for students exploring **Cloud Security & Log Analysis**.

---

## 🧱 System Architecture


AWS CloudTrail → Amazon S3 → Python Log Analyzer → Risk Classification Output

->The analyzer reads CloudTrail logs stored in S3, parses the JSON data, applies classification logic, and outputs categorized events (JSON/CSV).



## 🛠️ Prerequisites

Before running the project, ensure you have:

- ✅ **AWS Account** (to generate CloudTrail logs)  
- ✅ **CloudTrail Trail** configured to send logs to an S3 bucket  
- ✅ **Python 3.7+** installed  
- ✅ CloudTrail log files (in `.json.gz` format) downloaded or accessible locally  

You can also simulate events by performing actions in AWS services like **EC2** or **IAM**.

---

## ⚙️ Installation & Setup

1. **Clone this repository**
   bash
   git clone https://github.com/yourusername/cloud-log-risk-analyzer.git
   cd cloud-log-risk-analyzer


2. **Install dependencies**

  
   pip install pandas boto3
  

3. **Place your CloudTrail logs**

   * Download logs from your S3 bucket.
   * Place them inside a folder named `logs/`.

4. **Run the analyzer**

   python risk_analyzer.py


## 🧩 Tools & Technologies Used

| Tool / Service        | Purpose                                           |
| --------------------- | ------------------------------------------------- |
| **AWS CloudTrail**    | Captures and records AWS account activity as logs |
| **Amazon S3**         | Stores CloudTrail logs for processing             |
| **AWS EC2**           | Simulates AWS actions for testing                 |
| **Python 3.x**        | Core programming language                         |
| **Pandas**            | Parses and processes structured data              |
| **Gzip**              | Decompresses `.json.gz` CloudTrail log files      |
| **JSON Module**       | Parses and manipulates JSON log data              |
| **Boto3 (optional)**  | Automates AWS log retrieval if integrated         |
| **VS Code / PyCharm** | Development environment                           |
| **Git & GitHub**      | Version control and project hosting               |



## 📂 Project Structure

cloud-log-risk-analyzer/
│
├── risk_analyzer.py           # Main log analysis and risk classification script
├── custom_rules.json          # User-defined rules for classification
├── sample_logs/               # Example CloudTrail log files
├── outputs/                   # Processed results and categorized logs
├── README.md                  # Project documentation
└── requirements.txt           # Python dependencies

## 📊 Sample Output

================= Risk Summary =================
Total Logs Analyzed: 500
High Risk Events: 12
Medium Risk Events: 36
Low Risk Events: 452
===============================================

✅ Output saved as 'outputs/risk_summary.csv'


## 🧠 Future Enhancements

* 🌐 Add Flask-based web dashboard for visualization
* 🔐 Integrate AWS authentication for direct log fetching
* ⚙️ Include dynamic rule creation from frontend
* 📈 Add ML-based anomaly detection

---

## 🧾 License

This project is licensed under the **MIT License** – feel free to use, modify, and distribute it for educational or personal use.


## 👨‍💻 Author

**N. Thanmai**


