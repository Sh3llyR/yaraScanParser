# yaraScanParser


<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This script it a parsing tool for [Yara Scan Service](https://riskmitigation.ch/yara-scan/)'s JSON output file. Yara Scan Service allows you to quickly test your [YARA](https://yara.readthedocs.io/en/v3.4.0/index.html) rule against a large collection of malicious samples. It helps you assure your rule only matches the malware family you are looking to catch. The output is a JSON file containing all the matched samples. The JSON file contains a lot of information, and yaraScanParser is meant to help you parse it and maximize it's benefits.

yaraScanParser allows you to:
* Save time by parsing the Yara Scan Service results automatically
* Get information about wanted matches and false positives of your rule
* Get the matched files' hash values in a format the can be easily inserted to your Yara rule's metadata section



### Built With

* [Python](https://www.python.org/)



<!-- GETTING STARTED -->
## Getting Started

To use this tool, you must have Python installed.


### Installation

Clone the repo
   ```sh
   git clone https://github.com/Sh3llyR/yaraScanParser.git
   ```



<!-- USAGE EXAMPLES -->
## Usage

![Product Name Screen Shot][product-screenshot]

* Parameters -o and -m are OPTIONAL

Examples:
* python yaraScanParser.py -i yara_scan_service_results.json -o output.txt -m CobaltStrike
* python3 yaraScanParser.py -i yara_scan_service_results.json



<!-- CONTACT -->
## Contact

[![LinkedIn][linkedin-shield]][linkedin-url]

Project Link: [https://github.com/Sh3llyR/yaraScanParser](https://github.com/Sh3llyR/yaraScanParser)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Yara Scan Service](https://riskmitigation.ch/yara-scan/)
* [Yara Scan Service Github Repository](https://github.com/cocaman/yara-scan-service)
* [Img Shields](https://shields.io)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/shelly-raban-6baa2b1b9/
[product-screenshot]: Images/help.png
