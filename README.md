# 🚀 DLL Vuln Searcher 🛡️
Welcome to **DLL Vuln Searcher**, a Python script that uses web scraping techniques to search for vulnerabilities in the dependencies of different vendors from [security.snyk.io](https://security.snyk.io).

## 🌟 Features
- **Web Scraping**: Uses web scraping to extract detailed information about vulnerabilities.
- **Support for Multiple Vendors**: Designed to search for vulnerabilities in dependencies from various vendors, including NuGet, npm, Cargo, Maven. For more information, visit [security.snyk.io](https://security.snyk.io).
- **Flexible Input**: Reads dependencies from a text file provided by the user.

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.x installed on your machine.
- The following Python libraries:
  - `requests`
  - `re`
  - `time`
  - `datetime`
You can install them using pip:
```bash
pip install requests
```
> Note: `re`, `time`, and `datetime` are part of the Python standard library and do not need to be installed.

### 2. Using the Script

1. **Prepare Your Dependencies File**:
   - Create a `.txt` file containing the dependencies you want to check, each on a separate line. Example:
     ```
     Newtonsoft.Json
     NUnit
     ```

2. **Run the Script**:
   - When you run the script, it will ask you to enter the name of the text file containing the dependencies.
```bash
   python3 DLLVulnSearcher.py
```

3. **Provide the File Name**:
   - Enter the name of the text file when the script prompts you. Make sure the file is in the same directory as the script, or provide the full path.
   
### 3. Example Run

```plaintext
Enter the name of the dependencies file: example.txt
		RazorEngine
Vulnerability name: Arbitrary Code Execution
	Severity: High
	Affected component: razorengine
	Affected versions: [0,]
	Download: NuGet
	Publication date: 6 Mar 2022
		Microsoft.Owin
Vulnerability name: Denial of Service (DoS)
	Severity: High
	Affected component: microsoft.owin
	Affected versions: [,4.2.2)
	Download: NuGet
	Publication date: 31 Aug 2022
Vulnerability name: Denial of Service (DoS)
	Severity: High
	Affected component: microsoft.owin.security.cookies
	Affected versions: [,4.2.2)
	Download: NuGet
	Publication date: 31 Aug 2022
```

## 🔧 Customization
You can modify the script to adjust the vendors or the way dependencies are handled. This is just a starting point, and the possibilities are endless.

## 📄 License
This project is licensed under the MIT License. You can find more details in the LICENSE file.

## 🤝 Contributing
Contributions are welcome! If you have any improvements or suggestions, please open an issue or create a pull request.

## 📬 Contact
For any questions, feel free to reach out through my GitHub profile.

---
Thanks for using **DLL Vuln Searcher**! Together, let's make our dependencies more secure. 🛡️
---
Made with ❤️ by m4t1
---
**Note**: This project is not affiliated with or endorsed by Snyk. It is an independently created tool to help with vulnerability searching.
