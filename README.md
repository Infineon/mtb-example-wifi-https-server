# AnyCloud: HTTPS Server

This code example demonstrates the implementation of an HTTPS server with PSoC® 6 MCU and CYW43xxx connectivity devices.

It employs the [HTTPS Server](https://github.com/cypresssemiconductorco/http-server) middleware library, which takes care of all the underlying socket connections with the HTTPS client. In this example, the HTTPS server establishes a secure connection with a HTTPS client through SSL handshake. Once the SSL handshake completes successfully, the HTTPS client can make GET, POST, and PUT requests with the server.

## Requirements

- [ModusToolbox™ software](https://www.cypress.com/products/modustoolbox-software-environment) v2.1
- Programming Language: C
- Associated Parts: All [PSoC 6 MCU](http://www.cypress.com/PSoC6) parts

## Supported Kits

- [PSoC 6 Wi-Fi BT Prototyping Kit](https://www.cypress.com/CY8CPROTO-062-4343W) (CY8CPROTO-062-4343W) - Default target
- [PSoC 62S2 Wi-Fi BT Pioneer Kit](https://www.cypress.com/CY8CKIT-062S2-43012) (CY8CKIT-062S2-43012)

## Hardware Setup

This example uses the board's default configuration. See the kit user guide to ensure that the board is configured correctly.

**Note**: The PSoC 6 BLE Pioneer Kit (CY8CKIT-062-BLE) and the PSoC 6 WiFi-BT Pioneer Kit (CY8CKIT-062-WIFI-BT) ship with KitProg2 installed. ModusToolbox software requires KitProg3. Before using this code example, make sure that the board is upgraded to KitProg3. The tool and instructions are available in the [Firmware Loader](https://github.com/cypresssemiconductorco/Firmware-loader) GitHub repository. If you do not upgrade, you will see an error like "unable to find CMSIS-DAP device" or "KitProg firmware is out of date".

## Software Setup

- Install a terminal emulator if you don't have one. Instructions in this document use [Tera Term](https://ttssh2.osdn.jp/index.html.en).
- [OpenSSL](#prerequisites)

**Note:** This code example also uses the *cURL* utility to test the HTTPS server. This utility helps to send HTTPS GET, POST, and PUT requests to the server. The *cURL* utility (version 7.59.0) is already shipped with the [ModusToolbox™ software](https://www.cypress.com/products/modustoolbox-software-environment) v2.1; it is available under *{ModusToolbox install directory}/tools_\<version>/modus-shell/bin*).

## Using the Code Example

### In Eclipse IDE for ModusToolbox:

1. Click the **New Application** link in the Quick Panel (or, use **File** > **New** > **ModusToolbox Application**).

2. Pick a kit supported by the code example from the list shown in the **Project Creator - Choose Board Support Package (BSP)** dialog.

   When you select a supported kit, the example is reconfigured automatically to work with the kit. To work with a different supported kit later, use the **Library Manager** to choose the BSP for the supported kit. You can use the Library Manager to select or update the BSP and firmware libraries used in this application. 
   
   To access the Library Manager, right-click the application name from the Project Workspace window in the IDE, and select **ModusToolbox** > **Library Manager**. You can also access it from the **Quick Panel**.

   You can also just start the application creation process again and select a different kit.

   If you want to use the application for a kit not listed here, you may need to update the source files. If the kit does not have the required resources, the application may not work.

3. In the **Project Creator - Select Application** dialog, choose the example.

4. Optionally, update the **Application Name** and **Location** fields with the application name and local path where the application is created.

5. Click **Create** to complete the application creation process.

For more details, see the Eclipse IDE for ModusToolbox User Guide: *{ModusToolbox install directory}/ide_{version}/docs/mt_ide_user_guide.pdf*.

### In Command-line Interface (CLI):

1. Download and unzip this repository onto your local machine, or clone the repository.

2. Open a CLI terminal and navigate to the application folder.

   On Linux and macOS, you can use any terminal application. On Windows, navigate to the modus-shell directory (*{ModusToolbox install directory}/tools_\<version>/modus-shell*) and run *Cygwin.bat*.

3. Import the required libraries by executing the `make getlibs` command.

### In Third-party IDEs:

1. Follow the instructions from the [CLI](#in-command-line-interface-cli) section to download or clone the repository, and import the libraries using the `make getlibs` command.

2. Export the application to a supported IDE using the `make <ide>` command.

3. Follow the instructions displayed in the terminal to create or import the application as an IDE project.

For more details, see the "Exporting to IDEs" section of the ModusToolbox User Guide: *{ModusToolbox install directory}/ide_{version}/docs/mtb_user_guide.pdf*.

## Operation

1. Connect the board to your PC using the provided USB cable through the KitProg3 USB connector.

2. Open *secure_http_server.h* and modify the `WIFI_SSID`, `WIFI_PASSWORD`, and `WIFI_SECURITY_TYPE` macros to match the credentials of the Wi-Fi network that you want to connect to.

   All possible security types are defined in the `cy_wcm_security_t` structure in the *cy_wcm.h* file.

3. Open a terminal program and select the KitProg3 COM port. Set the serial port parameters to 8N1 and 115200 baud.

4. Program the board.

   - **Using Eclipse IDE for ModusToolbox:**

      1. Select the application project in the Project Explorer.

      2. In the **Quick Panel**, scroll down, and click **\<Application Name> Program (KitProg3)**.

   - **Using CLI:**

     From the terminal, execute the `make program` command to build and program the application using the default toolchain to the default target. You can specify a target and toolchain manually:
        ```
        make program TARGET=<BSP> TOOLCHAIN=<toolchain>
        ```

        Example:
        ```
        make program TARGET=CY8CPROTO-062-4343W TOOLCHAIN=GCC_ARM
        ```

        **Note**:  Before building the application, ensure that the *deps* folder contains the BSP file (*TARGET_xxx.lib*) corresponding to the TARGET. Execute the `make getlibs` command to fetch the BSP contents before building the application.

5. After programming, the application starts automatically. Verify that the following logs appear on the serial terminal:

   ```
   Info: ===================================
   Info: AnyCloud: HTTPS Server
   Info: ===================================

   WLAN MAC Address : A0:C9:A0:3D:D3:6A
   WLAN Firmware    : wl0: Jan 30 2020 21:41:53 version 7.45.98.95 (r724303 CY) FWID 01-5afc8c1e
   WLAN CLM         : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3 Creation: 2020-01-30 21:30:05
   WHD VERSION      : v1.90.2 : v1.90.2 : GCC 7.2 : 2020-04-13 02:49:57 -0500
   Info: Wi-Fi initialization is successful
   Info: Join to AP: WIFI_SSID
   Info: Successfully joined Wi-Fi network WIFI_SSID
   Info: Assigned IP address: 192.168.0.12
   Info: HTTPS server has successfully started. The server is running at URL https://mysecurehttpserver.local:50007
   ```

7. This code example uses a self-signed SSL certificate. The client needs to install the root certificate provided by the HTTPS server. The root certificate (*rootCA.crt*) is available under the *configs* folder in the current directory.

   Do the following to install the HTTPS server root certificate authority on the clients. In this code example, the HTTPS server has two type of clients: one uses the cURL utility while the other uses a web browser.

    - **cURL utility**:

        - Ensure that the *cURL* utility has access to the *rootCA.crt* file. cURL commands can be invoked from anywhere in the Cygwin shell by passing the *--cacert* parameter with the path of the *rootCA.crt* file in *cURL* commands. See Step 10.

    - **Web browser**:

        - Mozilla Firefox:
            - Select **Options** > **Privacy & Security** (Windows) or **Preferences** > **Privacy & Security** (macOS and Ubuntu).

            - Find the **Certificates** section and then click **View Certificates**. The browser displays the Certificate Manager dialog. 

            - Click **Import** and select the *rootCA.crt* file from the *configs* folder and click **Open**.

            - Trust this certificate authority to identify websites and email users and click **OK**.

            - The **rootCA.crt** is now installed.

        - Google Chrome and Internet Explorer on Windows:
            - Click **Win key + R** > type **certmgr.msc** and click **OK**. The Windows Certificate Manager application opens.

            - Navigate to the *Trusted Root Certification Authorities/Certificates* folder.

            - Go to **Action** > **All Tasks** > **Import** and click **Next**.

            - Select the *rootCA.crt* file from the *configs* folder. Make sure to change file type as **All Files** to find the *rootCA.crt* file. Click **Open**.

            - Select the certification store as **Trusted Root Certification Authorities** and click **Finish**.

            - Click **Yes** to the security warning window to acknowledge that you trust *rootCA.crt* to allow its websites and email users.

            The **rootCA.crt** is now installed.

        - Google Chrome (Ubuntu):
            - Select **Settings**  > **Show Advanced Settings** > **HTTPS/SSL**. Click **Manage Certificates** under **Security** tab.

            - In the Certificate Manager window, click **Import** under the **Authorities** tab.

            - Select the *rootCA.crt* file from the *configs* folder. Make sure to change file type as **All Files** to find the *rootCA.crt* file. Click **Open**.

            - Trust this certificate authority to identify websites and email users and click **OK**.

            The **rootCA.crt** is now installed.

        - Google Chrome (macOS):
            - Open **Finder** > **Applications** > **Utilities** > **Keychain Access**.

            - Select the **System** keychain.

            - Open **File** > **Import Items**, and import the certificate file *rootCA.crt* into the **System** keychain.

            - Right-click the certificate and select **Get Info**. A certificate information window appears.

            - Expand the **Trust** category and select **Always Trust** to trust this certificate authority.

        **Note**: Browsers might need a restart after importing the certificate.

8. Enter https://mysecurehttpserver.local:50007 in the browser to access the HTTPS server webpage.

9. Ensure that your PC is connected to the same Wi-Fi access point that you have configured in Step 2. 

10. Testing the HTTPS server.

    **Using Web Browser:**

    1. Make sure that the root CA certificate is installed on the web browser per Step 7.

    2. Enter the URL https://mysecurehttpserver.local:50007. This opens the HTML page; it will look like as follows:

       **Figure 1. HTTPS Web Page**

       ![](images/webpage.png)

         a. Click **Get LED status** to send an HTTPS `GET` command to the server running on the kit. The server returns the current LED status on the kit as a response. Note that entering the URL itself will send a `GET` command to the server to get the HTML page.

         b. Click **Toggle LED** to send an HTTPS `POST` command to the server running on the kit. The server acts on the command request and toggles the LED on the kit.

    **Using the cURL Utility:**

       1. Open *Cygwin.bat* from modus-shell directory (*{ModusToolbox install directory}/tools_\<version>/modus-shell*).

       2. Set the path to *rootCA.crt* in a variable.

          ```
          PATH_TO_ROOTCA="<Path to rootCA.crt file>"
          ```

       3. Use the following *cURL* commands to test HTTPS commands with the HTTPS server: 

          **HTTPS GET:** Get the kit's LED status (ON or OFF).

           ```
           curl --cacert $PATH_TO_ROOTCA -X GET https://mysecurehttpserver.local:50007 --output -
           ```
           Verify that the HTTPS server responds with the following HTML output. This contains the LED status (ON or OFF) of the kit.

           ```
           <!DOCTYPE html><html><head><title>HTTPS Server Demo</title></head><body><h1>HTTPS Server Demo</h1><form method="get"><fieldset><legend>HTTPS GET</legend><input type="submit" value="Get LED status"/><input type="text" name="led_status" value="OFF" size="3" readonly/></br></br></fieldset></br></form><form method="post"><fieldset><legend>HTTPS POST</legend><input type="submit" name="toggle_led" value="Toggle LED"/></br></br></fieldset></br></form></body></html>
           ```

          **HTTPS POST:** Toggle the LED (ON or OFF) on the kit.

           ```
          curl --cacert $PATH_TO_ROOTCA -X POST https://mysecurehttpserver.local:50007 --output -
           ```

          Verify that the HTTPS server responds with the following HTML output. The response contains the LED status (ON or OFF) of the last `GET` request.

          ```
          <!DOCTYPE html><html><head><title>HTTPS Server Demo</title></head><body><h1>HTTPS Server Demo</h1><form method="get"><fieldset><legend>HTTPS GET</legend><input type="submit" value="Get LED status"/><input type="text" name="led_status" value="OFF" size="3" readonly/></br></br></fieldset></br></form><form method="post"><fieldset><legend>HTTPS POST</legend><input type="submit" name="toggle_led" value="Toggle LED"/></br></br></fieldset></br></form></body></html>
          ```

          **HTTPS PUT:** Register a new HTTP resource. The HTTPS server creates a new resource called *myhellomessage*.

           ```
           curl --cacert $PATH_TO_ROOTCA -X PUT -d "/myhellomessage" https://mysecurehttpserver.local:50007 --output -
           ```

           Verify the newly created resource by sending an HTTPS `GET` request.
           ```
           curl --cacert $PATH_TO_ROOTCA -X GET https://mysecurehttpserver.local:50007/myhellomessage --output -
           ```
           Verify that the HTTPS server responds with a Hello text message.
           ```
           Hello - Message from HTTPS server!
           ```

## Debugging

You can debug the example to step through the code. In the IDE, use the **\<Application Name> Debug (KitProg3)** configuration in the **Quick Panel**. For more details, see the "Program and Debug" section in the Eclipse IDE for ModusToolbox User Guide: *{ModusToolbox install directory}/ide_{version}/docs/mt_ide_user_guide.pdf*.

## Design and Implementation

### Resources and Settings

The following ModusToolbox resources are used in this example.

**Table 1. Application Resources**

| Resource  |  Alias/Object     |    Purpose     |
| :------- | :------------    | :------------ |
| UART (HAL) |cy_retarget_io_uart_obj| UART HAL object used by Retarget-IO for Debug UART port |
| GPIO (HAL) | CYBSP_USER_LED | User LED |

This example uses the Arm® Cortex®-M4 (CM4) CPU of PSoC 6 MCU to start the HTTPS server task. At device reset, the default Cortex-M0+ (CM0+) application enables the CM4 CPU and configures the CM0+ CPU to go to sleep.

In this example, the HTTPS server establishes a secure connection with a web browser or cURL client through SSL handshake. During the SSL handshake, the server presents its SSL certificate for verification and verifies the incoming client identity. This example uses mDNS (Multicast Domain Name System) provided by the lwIP open-source TCP/IP network stack. mDNS helps in resolving the domain name of the HTTPS server to an IP address in the local network. This code example supports only IPv4 with mDNS.

You can define the maximum number of HTTPS page resources for the HTTPS server in the application Makefile, as shown below. The HTTPS server library maintains the database of pages based on this value.

```
DEFINES+=MAX_NUMBER_OF_HTTP_SERVER_RESOURCES=10
```

Note that if the `MAX_NUMBER_OF_HTTP_SERVER_RESOURCES` value is not defined in the application Makefile, the HTTPS server will set it to 10 by default. This code example does not define this parameter in the application Makefile; therefore, the application uses the default value of 10. This depends on the availability of memory on the MCU device.

### Creating a Self-Signed SSL Certificate

The HTTPS server demonstrated in this example uses a self-signed SSL certificate. This means that there is no third-party certificate issuing authority, commonly referred to as CA, involved in the authentication of the server. Clients connecting to the server must have a root CA certificate to verify and trust the websites defined by the certificate. Only when the client trusts the website, it can establish secure connection with the HTTPS server.

Do the following to generate a self-signed SSL certificate:

#### Prerequisites
The OpenSSL library is required to generate a self-signed certificate for the HTTPS server. Run the following command in your local environment to see if you already have OpenSSL installed.

```
which openssl
```
Install OpenSSL if the `which` command does not return a path.

| Operating System  |  Installation    |
| :------- | :------------    |
| Windows | [Windows OpenSSL installer](http://gnuwin32.sourceforge.net/packages/openssl.htm) |
| Ubuntu Linux |`apt-get install openssl`|
| macOS |[Homebrew](https://brew.sh/):`brew install openssl`|

#### Generate SSL Certificate and Private Key 
Run the following script to generate the self-signed SSL certificate and private key.

```
./generate_ssl_certs.sh
```
This will produce the following files:
- **mysecurehttpserver.local.crt** - HTTPS server certificate.
- **mysecurehttpserver.local.key** - HTTPS server private key.
- **rootCA.crt** - HTTPS server rootCA certificate to trust the client.
- **rootCA.key** - HTTPS server root key used for signing the certificate.

The HTTPS server should be configured to take *mysecurehttpserver.local.crt* as the certificate, *mysecurehttpserver.local.key* as the private key, and *rootCA.crt* as the rootCA certificate.

You can either convert the values to strings manually following the format shown in *source/secure_keys.h* or use the HTML utility available [here](https://github.com/cypresssemiconductorco/amazon-freertos/blob/master/tools/certificate_configuration/PEMfileToCString.html) to convert the certificates and keys from PEM format to C string format. You need to clone the repository from GitHub to use the utility.

The *rootCA.crt* should be installed on all the clients which are trying to communicate with the HTTPS server.

## Related Resources

| Application Notes                                            |                                                              |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| [AN228571](https://www.cypress.com/AN228571) – Getting Started with PSoC 6 MCU on ModusToolbox | Describes PSoC 6 MCU devices and how to build your first application with ModusToolbox |
| **Code Examples**                                            |                                                              |
| [Using ModusToolbox](https://github.com/cypresssemiconductorco/Code-Examples-for-ModusToolbox-Software) | [Using PSoC Creator](https://www.cypress.com/documentation/code-examples/psoc-6-mcu-code-examples) |
| **Device Documentation**                                     |                                                              |
| [PSoC 6 MCU Datasheets](https://www.cypress.com/search/all?f[0]=meta_type%3Atechnical_documents&f[1]=resource_meta_type%3A575&f[2]=field_related_products%3A114026) | [PSoC 6 Technical Reference Manuals](https://www.cypress.com/search/all/PSoC%206%20Technical%20Reference%20Manual?f[0]=meta_type%3Atechnical_documents&f[1]=resource_meta_type%3A583) |
| **Development Kits**                                         | Buy at www.cypress.com                                       |
| [CY8CKIT-062S2-43012](https://www.cypress.com/CY8CKIT-062S2-43012) PSoC 62S2 Wi-Fi BT Pioneer Kit | [CY8CPROTO-062S3-4343W](https://www.cypress.com/CY8CPROTO-062S3-4343W) PSoC 62S3 Wi-Fi BT Prototyping Kit |                                                             |
| **Libraries**                                                |                                                              |
| PSoC 6 Peripheral Driver Library (PDL) and docs                    | [psoc6pdl](https://github.com/cypresssemiconductorco/psoc6pdl) on GitHub |
| Cypress Hardware Abstraction Layer (HAL) Library and docs          | [psoc6hal](https://github.com/cypresssemiconductorco/psoc6hal) on GitHub |
| RetargetIO - A utility library to retarget the standard input/output (STDIO) messages to a UART port | [retarget-io](https://github.com/cypresssemiconductorco/retarget-io) on GitHub |
| **Middleware**                                               |                                                              |
| http-server                                    | [http-server](https://github.com/cypresssemiconductorco/http-server) on GitHub |
| Wi-Fi Connection Manager (WCM)                                    | [wifi-connection-manager](https://github.com/cypresssemiconductorco/wifi-connection-manager) on GitHub |
| Wi-Fi Middleware core | [wifi-mw-core](https://github.com/cypresssemiconductorco/wifi-mw-core) on GitHub |
| Connectivity-Utilities                                    | [connectivity-utilities](https://github.com/cypresssemiconductorco/connectivity-utilities) on GitHub |
| Links to all PSoC 6 MCU Middleware                               | [psoc6-middleware](https://github.com/cypresssemiconductorco/psoc6-middleware) on GitHub |
| **Tools**                                                    |                                                              |
| [Eclipse IDE for ModusToolbox](https://www.cypress.com/modustoolbox)     | The cross-platform, Eclipse-based IDE for IoT designers that supports application configuration and development targeting converged MCU and wireless systems.  |
| [PSoC Creator](https://www.cypress.com/products/psoc-creator-integrated-design-environment-ide) | The Cypress IDE for PSoC and FM0+ MCU development.            |

## Other Resources

Cypress provides a wealth of data at www.cypress.com to help you select the right device, and quickly and effectively integrate it into your design.

For PSoC 6 MCU devices, see [How to Design with PSoC 6 MCU - KBA223067](https://community.cypress.com/docs/DOC-14644) in the Cypress community.

## Document History

Document Title: *CE230422 - AnyCloud: HTTPS Server*

| Version | Description of Change |
| ------- | --------------------- |
| 1.0.0   | New code example      |

------

All other trademarks or registered trademarks referenced herein are the property of their respective owners.

![banner](images/ifx-cy-banner.png)

-------------------------------------------------------------------------------

© Cypress Semiconductor Corporation, 2020. This document is the property of Cypress Semiconductor Corporation and its subsidiaries ("Cypress"). This document, including any software or firmware included or referenced in this document ("Software"), is owned by Cypress under the intellectual property laws and treaties of the United States and other countries worldwide. Cypress reserves all rights under such laws and treaties and does not, except as specifically stated in this paragraph, grant any license under its patents, copyrights, trademarks, or other intellectual property rights. If the Software is not accompanied by a license agreement and you do not otherwise have a written agreement with Cypress governing the use of the Software, then Cypress hereby grants you a personal, non-exclusive, nontransferable license (without the right to sublicense) (1) under its copyright rights in the Software (a) for Software provided in source code form, to modify and reproduce the Software solely for use with Cypress hardware products, only internally within your organization, and (b) to distribute the Software in binary code form externally to end users (either directly or indirectly through resellers and distributors), solely for use on Cypress hardware product units, and (2) under those claims of Cypress's patents that are infringed by the Software (as provided by Cypress, unmodified) to make, use, distribute, and import the Software solely for use with Cypress hardware products. Any other use, reproduction, modification, translation, or compilation of the Software is prohibited.  
TO THE EXTENT PERMITTED BY APPLICABLE LAW, CYPRESS MAKES NO WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, WITH REGARD TO THIS DOCUMENT OR ANY SOFTWARE OR ACCOMPANYING HARDWARE, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. No computing device can be absolutely secure. Therefore, despite security measures implemented in Cypress hardware or software products, Cypress shall have no liability arising out of any security breach, such as unauthorized access to or use of a Cypress product. CYPRESS DOES NOT REPRESENT, WARRANT, OR GUARANTEE THAT CYPRESS PRODUCTS, OR SYSTEMS CREATED USING CYPRESS PRODUCTS, WILL BE FREE FROM CORRUPTION, ATTACK, VIRUSES, INTERFERENCE, HACKING, DATA LOSS OR THEFT, OR OTHER SECURITY INTRUSION (collectively, "Security Breach"). Cypress disclaims any liability relating to any Security Breach, and you shall and hereby do release Cypress from any claim, damage, or other liability arising from any Security Breach. In addition, the products described in these materials may contain design defects or errors known as errata which may cause the product to deviate from published specifications. To the extent permitted by applicable law, Cypress reserves the right to make changes to this document without further notice. Cypress does not assume any liability arising out of the application or use of any product or circuit described in this document. Any information provided in this document, including any sample design information or programming code, is provided only for reference purposes. It is the responsibility of the user of this document to properly design, program, and test the functionality and safety of any application made of this information and any resulting product. "High-Risk Device" means any device or system whose failure could cause personal injury, death, or property damage. Examples of High-Risk Devices are weapons, nuclear installations, surgical implants, and other medical devices. "Critical Component" means any component of a High-Risk Device whose failure to perform can be reasonably expected to cause, directly or indirectly, the failure of the High-Risk Device, or to affect its safety or effectiveness. Cypress is not liable, in whole or in part, and you shall and hereby do release Cypress from any claim, damage, or other liability arising from any use of a Cypress product as a Critical Component in a High-Risk Device. You shall indemnify and hold Cypress, its directors, officers, employees, agents, affiliates, distributors, and assigns harmless from and against all claims, costs, damages, and expenses, arising out of any claim, including claims for product liability, personal injury or death, or property damage arising from any use of a Cypress product as a Critical Component in a High-Risk Device. Cypress products are not intended or authorized for use as a Critical Component in any High-Risk Device except to the limited extent that (i) Cypress's published data sheet for the product explicitly states Cypress has qualified the product for use in a specific High-Risk Device, or (ii) Cypress has given you advance written authorization to use the product as a Critical Component in the specific High-Risk Device and you have signed a separate indemnification agreement.  
Cypress, the Cypress logo, Spansion, the Spansion logo, and combinations thereof, WICED, PSoC, CapSense, EZ-USB, F-RAM, and Traveo are trademarks or registered trademarks of Cypress in the United States and other countries. For a more complete list of Cypress trademarks, visit cypress.com. Other names and brands may be claimed as property of their respective owners.
