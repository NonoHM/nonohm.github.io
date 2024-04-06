---
layout: post
title: THM Security Principles
tags: [THM, Security Engineer]
author: NonoHM
date: 2024-01-31 18:07:37
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

Security has become a buzzword and everyone wants to claim their product is. In order to make our own products as secure as possible, we should know the adversaries attacks, tactics and techniques to implement appropriate security controls.

The objective of this room is to:

- Explain the security functions: Confidentiality, Integrity and Availability (CIA).
- Present the opposite of the security triad, CIA: Disclosure, Alteration, and Destruction/Denial (DAD).
- Introduce the fundamental concepts of security models, such as the Bell-LaPadula model.
- Explain security principles such as Defence-in-Depth, Zero Trust, and Trust but Verify.
- Introduce ISO/IEC 19249.
- Explain the difference between Vulnerability, Threat, and Risk.

## Task 2 - CIA

The "CIA triad" is the acronym for Confidentiality, Integrity and Availability.

1. **Confidentiality**: It ensures only the intended persons have access to the material.
2. **Integrity**: It ensures the material has not been modified by anyone.
3. **Availability**: It ensures the material is available when needed.

Examples:

- Confidentiality: The credit card number can only be used by the trusted shopping site and can't be viewed by third-party.
- Integrity: The data sent via the form must not be changed, i.e, a shipping address.
- Availability: The order and website have to be available anytime when the customer needs to. He may go to another one if the online shop is down.

### Beyond CIA

Another thing that can be useful to consider as well as the CIA Triad, is the Authenticity and Non-Repudiation.

- **Authenticity**: It ensures the document/material is from the claimed source.
- **Non-Repudiation**: It ensures the original author can't deny being the original author of the material/data...

Some of these can be achieved using:

|     Service     |                      Symetric Cryptography                     | Asymetric Cryptography                 |
|:---------------:|:--------------------------------------------------------------:|----------------------------------------|
| Confidentiality | Block or stream encryption using password/PSK (Pre-Shared Key) | Public key encryption via key exchange |
|    Integrity    |             Message Authentication Code (MAC/HMAC)             | Digital signature                      |
|   Authenticity  |                      Challenge - Response                      | Digital signature                      |
| Non-Repudiation |                                X                               | Digital signature                      |

### Parkerian Hexad

In 1998, Donn Parker proposed the Parkerian Hexad, a set of six security elements. They are:

1. Availability
2. Utility
3. Integrity
4. Authenticity
5. Confidentiality
6. Possession

For the non-covered topics:

- **Utility**: This focuses on the utility of the information, i.e, an encrypted disk without the decryption key is "useless".
- **Possession**: This element requires that we protect the information from unauthorized taking, copying, or controlling, i.e, a ransomware which successfully encrypted a disk, lead to the loss of possession of it.

### Questions

**Click on "View Site" and answer the five questions. What is the flag that you obtained at the end?** 

MCQ Answers: C, A, I, C, I

*Answer: `THM{CIA_TRIAD}`*

## Task 3 - DAD

The security of a system is attacked through one of several means, disclosure, alteration and/or destruction of data. This forms the DAD triad, the "opposite" of the CIA triad.

- **Disclosure**: The lack of confidentiality.
- **Alteration**: The lack of integrity.
- **Destruction/Denial**: The opposite of availability.

Therefore, building defenses against DAD returns to building CIA in the system. A good security system is the perfect balance between these.

### Questions

**The attacker managed to gain access to customer records and dumped them online. What is this attack?**

*Answer: `Disclosure`*

**A group of attackers were able to locate both the main and the backup power supply systems and switch them off. As a result, the whole network was shut down. What is this attack?**

*Answer: `Destruction/Denial`*

## Task 4 - Fundamental Concepts of Security Models

Now we have learnt some security concepts, we might ask how to apply these ? Three foundational security models can help us as:

- Bell-LaPadula Model
- The Biba Integrity Model
- The Clark-Wilson Model

### Bell-LaPadula Model

The Bell-LaPadula Model aims to achieve **confidentiality** with three rules:

- **Simple Security Property**: Referred as "No read up". A lower security level object cannot access to a higher security level one.
- **Star Security Property**: Referred as "No write down". A higher security level cannot write an object at a lower level.
- **Discretionary-Security Property**: This property uses an access matrix to allow read/write operations.

With these rules, we can send information from lower levels "Write up" and receive information from lower ones "Read down". The limitation is that model is not designed for file sharing.

### Biba Model

The Biba Model aims to achieve **integrity** by specifying two rules:

- **Simple Integrity Property**: "No read down", a higher level cannot read information from lower levels.
- **Star Integrity Property**: "No write up", a lowel level cannot write information for higher levels.

These rules contrast with the Bell-LaPadula model and this model suffers that it can't handle internal threats.

### Clark-Wilson Model

The Clark-Wilson Model aims to achieve **integrity** by using four concepts:

- **Constrained Data Item (CDI)**: The data type which integrity has to be preseved.
- **Unconstrained Data Item (UDI)**: All data types beyond CDI such as user input.
- **Transformation Procedures (TPs):**: Programmed operations such as read and write, and should maintain CDI's integrity.
- **Integrity Verification Procedures (IVPs)**: Procedures check to ensure validity of CDIs.

There is more models such as:

- Brewer and Nash model
- Goguen-Meseguer model
- Sutherland model
- Graham-Denning model
- Harrison-Ruzzo-Ullman model

### Questions

**Click on "View Site" and answer the four questions. What is the flag that you obtained at the end?**

*A = Bell-LaPadula*
*B = Biba*

MCQ answers: B, A, A, B

*Answer: `THM{SECURITY_MODELS}`*

## Task 5 - Defence-in-Depth

Defence-in-Depth refers to creating a Multi-Layer Security using multiples measures at different levels to protect systems and data. This can include thing like firewalls, encryption, access controls, monitoring systems... 
Moreover, this is like having multiple locks on different doors in the same house; this approach help to mitigate risks, reduces the likelihood of successful attacks, and enhances overall security resilience.

## Task 6 - ISO/IEC 19249

This standard, ISO/IEC 19249, has been made by the International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC). It is named *Information technology - Security techniques - Catalogue of architectural and design principles for secure products, systems and applications* and his purpose is to have a better idea of what international organizations would teach regarding security principles.

It lists five architectural principles:

1. **Domain Separation**: Every set of related components is grouped as a single entity. Components can be applications, data or other ressources. Each entity will have its own domain and be assigned a common set of security attributes. Example: Ring architecture of Operating Systems (Kernel/User mode).
2. **Layering**: By splitting a system into different layers, it becomes possible to impose security at different levels. This is used in the OSI model, which splits the networking function into 7 layers.
3. **Encapsulation**: Like in OOP, direct manipulation of data should be prevented by providing an abstraction like a method to safely manipulate the data. This is made by using an API to interface with an application.
4. **Redundancy**: This principle ensures availability and integrity of data by putting backup or RAID configurations into systems.
5. **Virtualization/Containerization**: The generic concept is to share a single set of hardware among multiple operating systems. They are mainly used for their sandboxing capabilities to test programs or run isolated applications. Unlike virtualization, containerization provides the same kernel for multiple lightweight sandboxes and is more flexible than virtualization but needs a security emphasis on the shared kernel.

ISO/IEC 19249 teaches five design principles:

1. **Least Privilege**: The principle teaches the fact of supplying the least amount of permissions for someone to carry out their task and nothing more.
2. **Attack Surface Minimisation**: This represent the vulnerabilites risks aimed to be minimized; i.e, only run the needed services on Linux.
3. **Centralized Parameter Validation**: Checking and validation when receiving input, especially from user is crucial in order to prevent things like SQL Injection or Remote Code Execution. This needs to be centralized within one library or system.
4. **Centralized General Security Services**: Centralizing services like authentication service is crucial to prevent creating failure and to facilitate the authorization process.
5. **Preparing for Error and Exception Handling**: Whenever we build a system, we should take into account that errors and exceptions do and will occur and it needs to be fail safe, like traffic blocking and not leak confidential/error information.

### Questions

**Which principle are you applying when you turn off an insecure server that is not critical to the business?**

*Answer: `2`*

**Your company hired a new sales representative. Which principle are they applying when they tell you to give them access only to the company products and prices?**

*Answer: `1`*

**While reading the code of an ATM, you noticed a huge chunk of code to handle unexpected situations such as network disconnection and power failure. Which principle are they applying?**

*Answer: `5`*

## Task 7 - Zero Trust versus Trust but Verify

Trust is very complex topic, we can't really function without trust. If we mistrust a hardware, we stop using it completely and making a loss for a company.
Two security principles that are of interest to us regarding trust:

- Trust but Verify
- Zero Trust

1. **Trust but Verify**: This principle teaches that an entity should alawys been verified even if it is trusted. Verifying usually requires proper logging mechanisms and log checking, this is manly made by automated security mechnisms such as proxy and IDS.
2. **Zero Trust**:  This one treats trust as a vulnerabity, so it tries to eliminate the risk by always checking before accessing to an entity like with authentication and authorization mechanisms. This leds to a more contained damage if occured. The design of Zero Trust is microsegmentation; a network segment can be as small as a single host, so communication between each segment requires, authentication, ACL checks and maybe more.

## Task 8 - Threat versus Risk

There are three terms that we need to take note of to avoid any confusion.

- **Vulnerability**: Vulnerable means susceptible to attack or damage. In information security, a vulnerability is a weakness.
- **Threat**: A threat is a potential danger associated with this weakness or vulnerability.
- **Risk**: The risk is concerned with the likelihood of a threat actor exploiting a vulnerability and the consequent impact on the business.

Example - Showroom:

- Vulnerability: Weakness of standard glass
- Threat: The glass can be broken
- Risk: Stealing and impact on the business

## Task 9 - Conclusion 

In this room, we covered various principles and concepts related to security like CIA Triad and authenticity/nonrepudiation, its antagonist DAD. Moreover, we have seen three security models like Bell-LaPadula for confidentiality, the ISO/IEC 19249 standard, and security principles such as defence in depth, trust but verify, and zero trust.