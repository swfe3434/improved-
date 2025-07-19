# Instagram Report Bot

This script is a Python-based bot for reporting Instagram accounts. It provides two modes of operation: "Battle Arc Mode" for mass reporting a single user, and "Noti Claiming Mode" for reporting multiple users with a single reason.

## Features

-   **Two Reporting Modes:**
    -   **Battle Arc Mode:** Report a single user multiple times.
    -   **Noti Claiming Mode:** Report multiple users for the same reason.
-   **Command-Line Interface:** The script can be run with command-line arguments for ease of use.
-   **Session Management:** The script saves your session to a file to avoid logging in every time.
-   **Rate Limiting Handling:** The script has a built-in mechanism to handle rate limiting by Instagram.
-   **Deobfuscated and Refactored:** The original obfuscated code has been deobfuscated and refactored for better readability and maintainability.

## Disclaimer

This script is for educational purposes only. The developers are not responsible for any misuse of this script. Use at your own risk. Abusing this script may violate Instagram's terms of service and could lead to the suspension of your account.

## Prerequisites

-   Python 3.6+
-   `requests`
-   `cryptography`
-   `rich`

You can install the required packages using pip:

```bash
pip install requests cryptography rich
```

## Usage

You can run the script with command-line arguments or by entering the required information when prompted.

### Command-Line Arguments

```bash
python report_deobfuscated.py [options]
```

**Options:**

-   `-u, --username`: Your Instagram username.
-   `-p, --password`: Your Instagram password.
-   `-s, --secret`: The secret key for the script.
-   `-m, --mode`: The reporting mode (`battle` or `noti`).
-   `-t, --targets`: The target username(s).
-   `-r, --reason`: The report reason (a number from 1 to 8).
-   `-n, --num-reports`: The number of reports to send in "Battle Arc Mode".

**Report Reasons:**

1.  Spam
2.  Nudity
3.  Hate Speech
4.  Bullying
5.  Self-harm
6.  Violence
7.  Illegal Goods
8.  Intellectual Property

### Interactive Mode

If you run the script without any arguments, you will be prompted to enter the required information.

```bash
python report_deobfuscated.py
```

## How It Works

1.  **Deobfuscation:** The original script was heavily obfuscated. The first step was to deobfuscate the code to understand its functionality.
2.  **Refactoring:** The code was refactored into a more modular and maintainable structure. An `InstagramAPI` class was created to handle all interactions with the Instagram API.
3.  **Security:** The hardcoded secret key was removed, and the user is now prompted for it. A warning is also displayed to the user about the risks of entering their credentials.
4.  **User Experience:** A command-line interface was added using `argparse` to make the script more flexible and easier to use.
5.  **Error Handling and Logging:** More specific error handling and logging were added to provide better feedback and debugging information.

## Contributing

Contributions are welcome! If you have any suggestions or improvements, please feel free to open an issue or submit a pull request.
