---
layout: post
title: 'THM DFIR: An Introduction'
tags: [THM, Digital Forensics, Incident Response]
author: NonoHM
date: 2024-11-21 18:03:54
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

Firstly, security breaches and incidents happen despite the security teams trying their best to avoid them. The prudent approach is to prepare for the time an accident could happen so we are not caught off-guard. Consequently, when an incident happens, it is essential to identify footprints left by an attacker, in order to determine the scope of compromise in an environment, and restore it to the state it was before the incident occured. Hence, this is where Digital Forensics and Incident Response (DFIR) comes to place.

In this room, we will cover the following topics:

- Introduction fo DFIR
- Some basic concepts used in the DFIR field
- The Incident Response processes used in the industry
- Some of the tools used for DFIR

## Task 2 - The need for DFIR

> **Definitions**  
> **Forensics :** Application of scientific methods and techniques to investigate crimes and present evidence in court. It involves analyzing both physical, digital or biological evidence to uncover facts and support legal proceedings.  
> **Incident :** An unexpected event which can disrupt the general operation but does not necessarily lead to serious damages or major consequences.  
> **Accident :** A sudden, unforeseen event that results in damage, injury or loss of life or property.  

### What is DFIR

As already mentioned, DFIR stands for **Digital Forensics and Incident Response**. This field covers the **collection of forensic artifacts from digital devices** such as computers, media devices and smartphones to **investigate an incident**. This field helps Security Professionals identify footprints left by an attacker when a security incident occurs, use them to **determine the extent of compromise** in a environment and **restore the environment** to the state it was before the incident occured.

### The need for DFIR

DFIR helps security professionals in various ways, some of which are summarized below:

- **Finding evidence of attacker activity** in the network and sifting false alarms from actual incidents.
- **Robustly removing the attacker** to erase its foothold from the network.
- **Identifying the extent and timeframe of a breach**. This helps in communicating with relevant stakeholders.
- **Finding the loopholes** that led to the breach. What needs to be changed to avoid another on in the future ?
- **Understanding attacker behavior** to pre-emptively block further intrusion attempts by the attacker.
- **Sharing information about the attacker** with the community.

### Who performs DFIR ?

As the name suggests, DFIR require expertise in both Digital Forensics and Incident Response. Dividing these two fields this way, the following skillset is needed to become a DFIR profesisonal :

- **Digital Forensics :** These profesionnals are experts in identifying forensic artifacts or evidence of human activity in digital devices.
- **Incident Response :** Incident responders are experts in cybersecurity and leverage forensic information to identify the activity of interest from a security perspective.

DFIR professionals combine these domains to achieve their goals. Digital Forensics and Incident Response domains are often combined because they are highly interdependent. Incident Response leverages knowledge gained from Digital Forensics and Digital Forensics takes its goals and scope from the Incident Response process.

### Questions

**What does DFIR stand for?**

*Answer: `Digital forensics and Incident Response`*

**DFIR requires expertise in two fields. One of the fields is Digital Forensics. What is the other field?**

*Answer: `Incident Response`*

## Task 3 - Basic concepts of DFIR

### Artifacts

Artifacts are **pieces of evidence that point to an activity performed on a system**. When performing DFIR, they are collected to **support a hypothesis or to claim about attacker activity**. For example, a Windows *Registry key* used to maintain persistence on a system is considered as an artifact.  
Artifact collection is, therefore, an essential part of the DFIR process. Artifacts can be collected from Endpoint or Server file systems, memory r network activity.

In most corporate environments, Windows systems are mainly used for endpoints/servers such as *Active Directory domain controllers* or *MS Exchange mail servers*. On the other hand, Linux systems are mainly used for hosting services such as *web servers* or *databases*.

### Evidence Preservation

Maintaining the **integrity of evidences is a must** when performing DFIR. For this reason, certain best practices are established in the industry. We must note that **any forensic analysis contaminates** the evidence.  
For example, the evidence is first collected and **write-protected**. This copy is used for analysis, ensuring our original evidence is not contaminated and remains safe while analyzing. If the copy gets corrupted, we can always return and make a new copy from the preserved evidence.  

### Chain of custody

Afterward, when the evidence is collected, it must be made sure that it is kept in secure custody. Any person related to the investigation must not possess the evidence or it will **contaminate the chain of custody** (CoC) of the evidence. A contaminated CoC raises questions about the data integrity, hence **weakens the case** being built by adding unknown variables that can't be solved.  
For example, an hard drive image that has been handled by an unqualified third party weakens the evidence because we can not be sure it has been dealt correctly or contaminated.  

### Order of volatility

Digital evidence if **often volatile** and can be lost forever if not captured in time. Some sources are more volatile than others, i.e **RAM is more volatile than an SSD** since the RAM keeps data only as long as it remains powered on. Hence it is vital to understand the order of volatility of the different sources to **capture and preserve accordingly**. Thus, we might preserve the RAM before preserving hard drives because of its nature.

### Timeline creation

Once artifacts are collected and their integrity is preserved, we need to **present them understandably** to **fully use the contained information**. A timelime of events needs to be created in order to **put all the activities in chronological order**. This activity is called *Timeline Creation*. It provides perspective to the investigation and helps collate information from various sources to **create a story of how things happened**.

### Questions

**From amongst the RAM and the hard disk, which storage is more volatile?**

*Answer : `RAM`*

**Complete the timeline creation exercise in the attached static site. What is the flag that you get after completion?**

*Answer: `THM{DFIR_REPORT_DONE}`*

## Task 4 - DFIR Tools

### Eric Zimmerman's tools

Eric Zimmerman is a secuiry researcher who has written a few tools to help perform **forensic analysis on the Windows Platform**. These tools can be use in the [Windows Forensics 1](https://tryhackme.com/room/windowsforensics1) and [Windows Forensics 2](https://tryhackme.com/room/windowsforensics2) rooms.

### KAPE

*Kroll Artifact Parser and Extractor* is another beneficial tool by Eric Zimmerman. It automates the **collection and parsing of forensic artifacts**, which can help **create a timeline of events**. This tool is shown of in the [KAPE room](https://tryhackme.com/room/kape).

### Autopsy

*Autopsy* is an open-source forensics platform that helps **analyze data from digital media** like mobile devices, hard drives, removable drives... Various plugins speed up the forensic process by **extracting and presenting valuable information from raw data sources**. This tool is shown off in the [Autopsy room](https://tryhackme.com/room/btautopsye0).

### Volatility

*Volatility* is a tool that helps perform **memory analysis for memory captures** from both Windows and Linux OSes. It is a powerful tool that can help extract valuable information from the memory of a machine under investigation. This tool is shown off in the [Volatility room](https://tryhackme.com/room/volatility).

### Redline

*Redline* is an incident response tool developed and freely distributed by FireEye. This tool can **gather forensic data from a system** and help with collected forensic information. This tool is shown off in the [Redline room](https://tryhackme.com/room/btredlinejoxr3d).

### Velociraptor

*Velociraptor* is an open-source advanced **endpoint monitoring, forensics and response** platform. This tool is shown off in the [Velociraptor room](https://tryhackme.com/room/velociraptorhp).

## Task 5 - The Incident Response process

In *Security Operations*, the proment use of *Digital Forensics* is to perform *Incident Reponse*.

Different organizations have published standardized methods to perform Incident Reponse. NIST has defined a process in their [SP-800-61 Incident Handling guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf), which has the following steps:

1. **Preparation**
2. **Detection and Analysis**
3. **Containment, Eradication, and Recovery**
4. **Post-incident Activity**

Similarly, SANS has published an [Incident Handler's handbook](https://www.sans.org/white-papers/33901/). The handbook defines the steps as follows:

1. **Preparation**
2. **Identification**
3. **Containment**
4. **Eradication**
5. **Recovery**
6. **Lessons Learned**

Steps defined by SANS are often summarized as the *PICERL* acronym, making them easy to remember. SANS and NIST steps are identical. While NIST combines *Containment*, *Eradication* and *Recovery*, SANS separate them into different steps.

``` raw
+-------------------+     +-------------------+     +-------------------+     +-------------------+     +-------------------+     +-------------------+
|    Preparation    | --> |  Identification   | --> |    Containment    | --> |    Eradication    | --> |      Recovery     | --> |  Lessons Learned  |
+-------------------+     +-------------------+     +-------------------+     +-------------------+     +-------------------+     +-------------------+
```

Below is the explanation of the SANS *Incident Handler's* steps.

1. **Preparation:** Before an incident happens, preparation needs to be done so that everyone is ready in case of an incident. Preparation includes having the required people, processes, and technology to prevent and respond to incidents.
2. **Identification:** An incident is identified through some indicators in the identification phase. These indicators are then analyzed for False Positives, documented, and communicated to the relevant stakeholders.
3. **Containment:** In this phase, the incident is contained, and efforts are made to limit its effects. There can be short-term and long-term fixes for containing the threat based on forensic analysis of the incident that will be a part of this phase.
4. **Eradication:** Next, the threat is eradicated from the network. It has to be ensured that a proper forensic analysis is performed and the threat is effectively contained before eradication. For example, if the entry point of the threat actor into the network is not plugged, the threat will not be effectively eradicated, and the actor can gain a foothold again.
5. **Recovery:** Once the threat is removed from the network, the services that had been disrupted are brought back as they were before the incident happened.
6. **Lessons Learned:** Finally, a review of the incident is performed, the incident is documented, and steps are taken based on the findings from the incident to make sure that the team is better prepared for the next time an incident occurs.

### Questions

**At what stage of the IR process are disrupted services brought back online as they were before the incident?**

*Answer: `Recovery`*

**At what stage of the IR process is the threat evicted from the network after performing the forensic analysis ?**

*Answer: `Eradication`*

**What is the NIST-equivalent of the step called "Lessons learned" in the SANS process?**

*Answer: `Post-incident Activity`*

## Task 6 - Conclusion

To conclude, in this room we have learned about **Digital Forensics and Incident Response (DFIR)** and its crucial role in the world of cybersecurity. We explored various key concepts and processes that are essential when dealing with security incidents, such as **artifacts**, **evidence preservation**, **chain of custody**, **order of volatility** and **timeline creation**.

We also delved into some of the most widely used tools in the industry, including **KAPE**, **Autopsy**, and **Volatility**, and discussed their applications in real-world incident response scenarios.

In addition, we covered the **PICERL process**—the standard process for incident response that helps organizations effectively handle and recover from security breaches. The steps include **Preparation**, **Identification**, **Containment**, **Eradication**, **Recovery**, and **Lessons Learned**. Each of these phases is essential for ensuring that security incidents are handled efficiently and with minimal damage.

Ultimately, DFIR professionals help organizations **detect**, **respond to**, and **recover from** cyber incidents, and their role continues to grow as cyber threats evolve. By understanding the key concepts, tools, and processes involved in DFIR, we are better equipped to protect and respond to security incidents in the future.