# Remote Deployment Tool

A simple yet powerful Windows desktop application for remotely deploying executables and managing their associated services on multiple machines simultaneously.

This tool provides a user-friendly graphical interface (GUI) to automate the process of stopping a service, replacing its executable file, and restarting it, or creating and starting the service if it doesn't exist.

![image](https://placehold.co/800x500/f0f0f0/333333?text=App+Screenshot+Here)

---

## Features

- **Multi-Host Deployment:** Deploy files to multiple hostnames or IP addresses at the same time.
- **Parallel Execution:** Utilizes multithreading to perform deployments on all hosts simultaneously, significantly speeding up the process.
- **Automated Service Management:**
    - Automatically stops the target service if it exists.
    - Replaces the executable file.
    - Restarts the existing service.
    - Creates and starts the service if it does not exist.
- **Real-time Logging:** View the status of each deployment in a detailed on-screen log.
- **Persistent CSV Logging:** All actions are automatically recorded in a `deployment_log.csv` file for auditing and troubleshooting.
- **Portable:** Can be run as a simple Python script or compiled into a single, standalone `.exe` file.

---

## Prerequisites

1.  **Windows Environment:** This tool is designed for Windows and uses Windows-specific commands.
2.  **Administrator Privileges:** You **must** run this application with administrator rights to perform remote service management.
3.  **Network Access:** The machine running the tool must have network access to the target hosts, and firewalls must allow the necessary connections (e.g., for file sharing - port 445).
4.  **PsExec:** The tool requires `psexec.exe` from the official Microsoft [PsTools Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools).

---

## Setup and Usage

### 1. Folder Setup

Before running the application, place the `psexec.exe` file in the **same directory** as the application (`deployment_tool.py` or `deployment_tool.exe`).

Your folder structure should look like this:

/RemoteDeploymentTool/|-- deployment_tool.py  (or deployment_tool.exe)|-- psexec.exe
### 2. Running the Application

**Crucial Step:** Right-click the application file (`.py` or `.exe`) and select **"Run as administrator"**.

### 3. Using the Interface

1.  **Source Executable:** Click "Browse..." to select the `.exe` file you want to deploy from your local machine.
2.  **Target Hostnames:** Enter the hostnames or IP addresses of the target machines, with each one on a new line.
3.  **Destination Path:** Specify the full path on the target machines where the executable should be copied (e.g., `C:\Program Files\MyApp\`). The script will automatically handle the conversion to a network path (e.g., `\\hostname\C$\...`) for the copy operation.
4.  **Service Name:** Enter the exact name of the Windows service associated with the executable.
5.  **Deploy:** Click the "Deploy" button to begin the simultaneous deployment to all specified hosts.

---

## How It Works

The application leverages two standard Windows command-line tools:

-   **PsExec:** Used to remotely execute commands on the target machines. This is how the script runs `sc` (Service Control) commands to query, stop, create, and start the Windows service.
-   **Robocopy (Robust File Copy):** Used to reliably copy the executable file over the network. Robocopy is resilient to network interruptions and is the professional standard for automated file transfers on Windows.

---

## Building from Source

To create a standalone `deployment_tool.exe` from the Python script (`.py`), you can use PyInstaller.

1.  **Install PyInstaller:**
    ```bash
    pip install pyinstaller
    ```

2.  **Navigate to the project directory** in your command prompt.

3.  **Run the build command:**
    ```bash
    pyinstaller --onefile --windowed --add-data "psexec.exe;." deployment_tool.py
    ```
    - `--onefile`: Bundles everything into a single executable.
    - `--windowed`: Prevents a console window from appearing when the GUI is run.
    - `--add-data "psexec.exe;."`: Finds `psexec.exe` and includes it in the final package.

4.  Your final `.exe` will be located in the `dist` folder.


## License

This project is licensed under the MIT License. See the LICENSE file for details.
