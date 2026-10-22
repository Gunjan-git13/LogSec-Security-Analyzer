\# LogSec — Log Security Analyzer



LogSec is a Python Flask-based web application designed to analyze log files, identify suspicious login activity, and highlight potential security threats through an interactive dashboard.



\## Features



\* \*\*Log Analysis:\*\* Analyze supported log files through a web interface.

\* \*\*Failed Login Detection:\*\* Identify repeated failed login attempts.

\* \*\*Suspicious IP Detection:\*\* Highlight IP addresses associated with repeated login failures.

\* \*\*Interactive Dashboard:\*\* Display log statistics, charts, and security alerts.

\* \*\*Live Log Monitoring:\*\* Refresh and inspect monitored log files.

\* \*\*Analysis History:\*\* Review previous analyses.

\* \*\*CSV Export:\*\* Download analysis results for further review.

\* \*\*User Authentication:\*\* Register and log in to access the dashboard.



\## Technologies Used



\* Python

\* Flask

\* HTML

\* CSS

\* JavaScript

\* SQLite

\* Git and GitHub



\## Project Structure



```text

LogSecurityAnalyzer/

├── app.py

├── analyzer.py

├── auth.py

├── database.py

├── live\_monitor.py

├── sample\_logs.txt

├── monitored\_logs/

├── static/

│   ├── css/

│   └── js/

├── templates/

├── .gitignore

└── README.md

```



\## Requirements



\* Python 3.11 or a compatible Python version

\* pip

\* Git



\## Installation and Setup



1\. Clone the repository:



&#x20;  ```bash

&#x20;  git clone https://github.com/Gunjan-git13/LogSec-Security-Analyzer.git

&#x20;  ```



2\. Open the project directory:



&#x20;  ```bash

&#x20;  cd LogSec-Security-Analyzer

&#x20;  ```



3\. Create a virtual environment:



&#x20;  ```bash

&#x20;  python -m venv venv

&#x20;  ```



4\. Activate the virtual environment on Windows:



&#x20;  ```cmd

&#x20;  venv\\Scripts\\activate

&#x20;  ```



5\. Install the required dependencies:



&#x20;  ```bash

&#x20;  pip install Flask

&#x20;  ```



&#x20;  Install any additional dependencies required by the project.



6\. Start the application:



&#x20;  ```bash

&#x20;  python app.py

&#x20;  ```



7\. Open your browser and visit:



&#x20;  `http://127.0.0.1:5000`



\## How to Use



1\. Register a user account and log in.

2\. Open the dashboard.

3\. Select a supported log file.

4\. Analyze the file and review the statistics.

5\. Inspect security alerts and suspicious IP addresses.

6\. Review previous analyses and export results when needed.



\## Security Note



Use sample or authorized log data only. Do not upload passwords, secret keys, private databases, or sensitive production logs to a public repository.



\## Future Improvements



\* Reliable automatic dashboard refresh.

\* Expanded log format support.

\* More configurable detection rules.

\* Improved security alert filtering.

\* Additional monitoring and reporting capabilities.



\## Author



Gunjan Dandekar



