---
layout: post
title: THM Security Engineer Intro
tags: [THM, Security Engineer]
author: NonoHM
date: 2024-01-26 14:00:45
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

Security engineers form the backbone of a enterprise's cyber security.  

### Learning Objectives

- Why does the need for security engineers arise?
- What are the qualifications required to become a security engineer?
- What does a security engineer do in a typical day of work?

## Task 2 - What is a Security Engineer?

### Why Do Organizations Need Security?

While technology has made the life of organizations a lot easier, it also created a new type data and revenue for unethical hackers. We often hear about companies getting hacked or ransomed and other types of attacks. In response to these threats, digital security has been growing and some dedicate whole departments created and are still creating.

### The Role of a Security Engineer

A security engineer is someone who:

- Owns the overall security of an organization.
- Ensures that the organization's cyber security risk is minimized.
- Creates systems and strategies against cyber threats and secure network solutions.
- Periodically conducts tests to ensure the robustness of the infrastructure and correct if needed.
- Collaborates and coordinates with other teams to establish security protocols across the organization.

### Qualifications Required for a Security Engineer

When hiring a security engineer, organizations look for:

- 0-2 years of experience with IT administration, helpdesk, networks or security operations.
- Basic understanding of computer networks, operating systems, and programming.
- Basic understanding of security concepts such as Governance, Risk and Compliance (GRC).

### Questions

**Who ensures that an organization's cyber security risk is minimized at all times?**

*Answer: `Security Engineer`*

## Task 3 - Core Responsibilities of a Security Engineer  

### Asset Management/Asset Inventory

One of the primary steps in ensuring an organization's security is to manage and maintain an inventory of an enterprise's digital assets. It has to be regularly maintained, updated and it needs to include IP addresses, physical location, network's place, applications running, permissions and the asset owner details.

### Security Policies

A security engineer helps the creation of security policies based on:

- CIA (Confidentiality, Integrity, Availability) & DAD (Disclosure, Alteration, Destruction/Denial)
- Defence-in-Depth with multi-layer security
- ISO/IEC 19249 -> Domain Separation, Layering, Encapsulation, Redundancy, Virtualization, Least privilege, Attack Surface Minimisation, Centralized Parameter Validation, Centralized General Security Services, Centralized General Security Services
- Zero Trust / Trust but Verify
- Vulnerability / Threat / Risk -> Considreing these aspects 

> Ref: [Security Principles](https://tryhackme.com/room/securityprinciples)

### Secure by Design

The engineer understands that the security posture receives the most Return on Investment if he follows a secure-by-design philosophy. This means the implemntation of a Secure network Architecture and the hardenization of the machines as much as secure software development.

> Ref: [Windows Hardening](https://tryhackme.com/room/microsoftwindowshardening), [Linux Hardening](https://tryhackme.com/room/linuxsystemhardening), [Active Directory Hardening](https://tryhackme.com/room/activedirectoryhardening), [Secure Software Development Lifecycle](https://tryhackme.com/room/securesdlc)

### Security Assessment and Assurance

While securely designing a seure network and infrastructure, the job is far from done after that.
Security is hard work and requires continuous effort like regular security assessments, audits, red and purple teaming from internal and external structures, creating Request for Quotations.

### Questions

**Where are details about an organization's digital assets, such as name, IP address, and owner, stored?**

*Answer: `Asset inventory`*

**Sometimes security policies can't be followed because of business needs. What avenue does a security engineer have to fulfil business needs in these cases?**

*Answer: `Exceptions`*

**What philosophy, if followed, provides the most Return on Investment (ROI)?**

*Answer: `Secure by design`*

## Task 4 - Continuous Improvement

### Ensuring Awareness

A security engineer might be tasked to maintain a certain security awareness level in the company. Humans are the weakest link in an organization's company, therefore, he needs to periodically run awareness sessions targeting social engineering and other types of attacks.

### Managing Risks

Ignoring risks can lead to disruptions, data leakage, lawsuits, or other forms of risk. Therefore, a security engineer is often tasked with identifying security risks, determining their likelihood and impact, and finding solutions to minimize those risks. Sometimes, a decision has to be made because all risks can't be eliminated but some can be reduced and a clear justification is required.

### Change Management

To ensure a robust security posture, he has to keep track of changes in the organization's digital assets that can affect the security posture and takes measures to improve it, like a new module or an upgrade in the company's website.

### Vulnerability Management

When new software versions are released and older versions have vulnerabilities found, his job is to monitor current ones and to plan the needed patch.

### Compliance and Audits

A part of a security engineer's duties is to ensure the compliance with regulatory and organizational requirements such as PCI-DSS, HIPAA, SOC2, ISO27001, NIST-800-53, and more,with bot internal or external auditors to detect any compliance issues.

### Questions

**What is considered the weakest link in an organization's security?**

*Answer: `Humans`*

**An organization's security evolves with the organization. What helps a security engineer keep the organization secure through these changes?**

*Answer: `Change management`*

## Task 5 - Additional Roles and Responsibilities 

### Managing Security Tooling

A security engineer might sometimes be required to configure or fine-tune security tools such as SIEMs, Firewalls, WAFs, EDRs, and more. He might also be a decision-maker about the needed tools and assessments.

### Tabletop Exercises

Certain scenarios are identified, exercised. In these, security team members must explain their respective role, like an employee getting hacked, and the security engineer is sometimes required to conduct these exercises.

### Disaster Recovery and Crisis Management

A robust security posture requires organizations to plan for untoward incidents, disasters, or crises. In any such scenario, the top priority for executive management is to maintain business continuity. A security engineer might be involved in disaster recovery, business continuity, and crisis management planning as part of the different compliance frameworks and the organization's internal policies.

### Questions

**What is a theoretical exercise carried out to gauge the operational readiness of an organization from a security point of view?**

*Answer: `Tabletop Exercise`*

**What is the priority of the management in case of a disaster or crisis?**

*Answer: `Business Continuity`*

## Task 6 - Walking in Their Shoes

Here, we experience what a security engineer might take while performing their duties.

### External Audit non-compliance report

**Observation 1**

Restrict accessibility of the servers to only required usage

**Observation 2**

Aggregate cloud logs in a single place. Forward the logs from that place to on-prem network using a restricted tunnel

### Vulnerability Assessment and Penetration testing report

**Observation 1**

Restrict accessibility of the server only through VPN or internal network

**Observation 2**

Restrict accessibility of the server only through VPN or internal network

**Observation 3**

Patch the vulnerability

### Question

**What is the flag shown on the completion of the static site?**

*Answer: `THM{S3CUR1TY_3NG1N33R5_R0CK}`*

## Task 7 - Conclusion

To conclude, a security engineer: 

- Owns the responsibility of an organization's cyber security.
- Ensures that the systems and infrastructure of an organization are built securely.
- Helps maintain this security posture through continuous improvement and changes in the organization's digital assets.
- Takes on additional roles and responsibilities to help other teams achieve the collective goal of a secure organization.