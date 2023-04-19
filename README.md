=========
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)]([https://www.gnu.org/licenses/gpl-3.0](https://github.com/dimaswell/Solaris-11-STIG/blob/main/LICENSE))
![Maintenance](https://img.shields.io/maintenance/yes/2023)

# macOS CIS Benchmarks Automation

This repository contains a collection of scripts that automate the checks for the CIS benchmarks on macOS 13 Ventura. These scripts are designed to be modular, making it easy to add, remove or modify individual checks as needed.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Structure](#structure)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

- macOS 13 Ventura
- Ability to run as root

## Installation

1. Clone the repository to your local machine:
```bash
git clone https://github.com/hackerman-jpeg/macOS-13-Automated-CIS-Benchmark.git
```
2. Navigate to the repository directory:
```bash
cd macOS-13-*
```
3. Ensure that the main script (main.sh) is executable:
```bash
chmod a+x main.sh
```

## Usage

To run the automated checks, execute the main.sh script:

```bash
./main.sh
```
The script will run through all checks and output the results in the terminal. Results will be marked as either PASSED or FAILED, depending on whether they meet the CIS benchmark criteria.

## Structure

The repository is organized as follows:

`checks/`: Contains check scripts organized by sections (e.g., section_1, section_2, etc.). Each check has a separate file (e.g., check_1_1.sh, check_1_2.sh, etc.).

`helper_functions/`: Contains a helper_functions.sh file that includes all helper functions required for the script.
main.sh: The main entry point for the script. This file sources the helper_functions.sh and required check files, and 
calls the check functions as needed.

`README.md`: Provides documentation and instructions for using the script.

## Contributing

Contributions are welcome! If you'd like to improve the existing checks, add new ones, or make any other enhancements, please submit a pull request or open an issue.