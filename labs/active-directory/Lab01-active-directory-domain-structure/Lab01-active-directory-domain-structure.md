# Active Directory Domain Structure and Administration

## 1. Introduction / Overview / Objective

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
The objective of this lab was to gain hands-on experience working in an Active Directory (AD) environment. While studying for the CompTIA Security+ exam, I learned the foundational ideas behind identity, authentication, and permission management. This lab helped me connect those concepts to actual system administration tasks by interacting with a live Windows domain environment.

The purpose of this lab was to build a practical understanding of Active Directory (AD) and how organizations manage users, computers, authentication, and security at scale. While I was already familiar with identity and authentication concepts from studying for the CompTIA Security+ exam, this lab allowed me to see how those concepts are applied in a real Windows domain environment.

I worked inside a virtualized Windows Server environment that functioned as the Domain Controller (DC). From here, I explored how AD stores objects such as users and computers, how Organizational Units (OUs) create structure, how permission delegation works, and how Group Policy Objects (GPOs) enforce consistent security configuration. This experience helped bridge the gap between theoretical knowledge and practical usage.

### Step-by-Step Walkthrough
- I logged into a Windows Server virtual machine configured as the Domain Controller (DC).
- I reviewed the main role of a DC, which is to authenticate users, apply Group Policy, and maintain the AD database.
- I confirmed the presence of Active Directory Users and Computers, DNS, and Group Policy Management tools.
- I prepared the environment to explore how AD organizes users, computers, groups, policies, and authentication workflows.

### Findings / Analysis
Active Directory centralizes identity and access control. Instead of configuring users and permissions separately on each workstation, everything is managed from a single point of control. This creates consistency, reduces administrative effort, and supports enterprise‑level security models.

### What I Learned
I learned how AD acts as the backbone of identity services in Windows-based networks. This reinforced Security+ concepts like AAA (Authentication, Authorization, and Accounting) and the importance of centralized directory infrastructure.

</details>

---

## 2. Understanding Windows Domains and Domain Controllers

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To understand the relationship between domain-joined systems and the Domain Controller, and how authentication requests are processed in a domain environment.

### Step-by-Step Walkthrough

I logged into the Domain Controller and reviewed the domain configuration. I noticed that the DC also hosted DNS, which matched what I learned during Security+. Kerberos authentication relies on DNS to resolve service names. I also reviewed how logging into a domain-connected machine contacts the DC to verify credentials.

- I examined the domain namespace and the server configuration.
- I confirmed that DNS was running on the DC, which is necessary for locating domain resources.
- I logged into a domain-joined workstation and observed that the login depended on contact with the DC.
- I reviewed how the DC stores user account information, verifies credentials, and processes access control.

### Findings / Analysis
Domains link all systems under one centralized identity platform. The DC is critical because it validates user access and enforces policy. Without a functioning DC, domain services and logins cannot occur. 

A domain centralizes identity and allows administrators to manage users and permissions from a single location. If the DC goes down, authentication fails—so the DC is critical infrastructure.

### What I Learned
I learned how authentication traffic flows in a domain and how DNS and Kerberos rely on the DC. This directly connected to Security+ topics around secure authentication systems.

I learned how domains unify authentication and how DNS and Kerberos rely on the DC. This connected directly to identity and AAA concepts from my Sec+ study.

</details>

---

## 3. Users, Groups, Computers, and Organizational Units (OUs)

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To understand how Active Directory organizes and manages objects such as users and computers, and how OUs help structure the domain for easier administration.

### Step-by-Step Walkthrough

---

I explored Active Directory Users and Computers (ADUC). I examined built‑in groups, the default Computers container, and the Domain Users group. I created new Organizational Units (OUs) to logically group users and machines, which makes policy assignment easier. I also reviewed the difference between:

- **Security Groups** (used for assigning permissions)
- **Organizational Units (OUs)** (used for structure and policy scoping)

---

<h4>(Step 1) I opened Active Directory Users and Computers (ADUC)</h4>

<p align="left">
  <img src="images/active-directory-domain-structure-01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 1</em>
</p>

I explored the default OUs: Users, Computers, and Built‑in security groups. Then, I reviewed how to create new Organizational Units (OUs) to group users and systems for easier management. I created example user accounts and placed them inside appropriate OUs. Finally, I reviewed group membership and access inheritance.


### Findings / Analysis
Security Groups handle permission assignment, while OUs provide structure and allow Group Policy to be applied at a targeted level. Organizing objects logically makes the domain easier to secure and maintain.

AD becomes much easier to manage when users and machines are organized clearly. Instead of assigning permissions individually, group‑based authorization saves time and reduces mistakes.

### What I Learned
I learned the key difference between Groups and OUs. Groups define *what someone can do*, while OUs define *where and how users and computers are organized for administration and policy purposes*.

I learned how OUs form the structure of AD while groups handle access control. This supported the principle of least privilege and role-based access management from Security+.

</details>

---

## 4. Delegation and Privilege Management

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To delegate administrative responsibility while maintaining the principle of least privilege.

### Step-by-Step Walkthrough

**What I did in a nutshell:** I removed an outdated OU by disabling “Protect object from accidental deletion.” Then, using the Delegation of Control Wizard, I assigned a user (Phillip) permission to manage only the Sales OU. I reset a user password and confirmed that Phillip could manage Sales accounts but not the rest of the domain.

---

<h4>(Step 1) Deleting an OU</h4>

---

**(Step 1-a):** For testing, I attempted to delete the "Research and Development" OU, but I wasn’t able to because Active Directory indicated that I either didn’t have the necessary permissions or the OU was protected from accidental deletion.

<p align="left">
  <img src="images/active-directory-domain-structure-02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 2</em>
</p>

---

**(Step 1-b)** Disabling accidental deletion protection feature

If the issue was simply a lack of permissions, there wouldn’t be anything I could do. However, assuming the OU was protected from accidental deletion, I disabled that protection. I went to the [View] tab and clicked [Advanced Features], which revealed additional containers. I then navigated to the THM OU (where the "Research and Development" child OU is located), right-clicked the "Research and Development" OU, selected [Properties], went to the [Object] tab, and unchecked "Protect object from accidental deletion".

<p align="left">
  <img src="images/active-directory-domain-structure-03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 3</em>
</p>

I went back into the THM OU folder, right-clicked the "Research and Development" child OU, and selected [Delete].

<blockquote>
A new modal appeared asking me to confirm deletion nothing that the OU had other objects in it. I clicked [Yes].
</blockquote>

<p align="left">
  <img src="images/active-directory-domain-structure-04.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 4</em>
</p>

It was successfully deleted.

<p align="left">
  <img src="images/active-directory-domain-structure-05.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 5</em>
</p>

---

<h4>(Step 2) Using the Delegation of Control Wizard feature</h4>

In this lab, I worked with Active Directory Organizational Units (OUs) to delegate limited administrative privileges to a support user. The goal was to allow the user Phillip, who is responsible for IT support, to reset passwords for users in the Sales OU without giving him full domain administrator rights.

<blockquote>
I learned that Active Directory allows OU-level delegation, which lets specific users or groups manage only the objects they are responsible for. This is typically used in organizations to allow Helpdesk or Support personnel to perform tasks such as password resets or user unlocks while maintaining the principle of least privilege.
</blockquote>

---

**(Step 2-a)**

I opened **Active Directory Users and Computers**, enabled **Advanced Features**, then right-clicked the "Sales" OU and selected [Delegate Control]. I selected the user Phillip (THM\phillip).

<blockquote>
I typed his first name ("Phillip"), then clicked [Check Names] which automatically entered his information
</blockquote>

<p align="left">
  <img src="images/active-directory-domain-structure-06.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 6</em>
</p>

---

**(Step 2-b)**

After selecting [OK], I selected Phillip’s account and delegated the “Reset user passwords and force password change at next logon” permission. This follows the principle of least privilege by only granting him the rights he needs to perform his role.

<p align="left">
  <img src="images/active-directory-domain-structure-07.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 7</em>
</p>

---

**(Step 2-c)**

To test the delegation, I logged into the domain using Phillip’s account. During the RDP login, I specified the domain "thm.local"

<blockquote>
Every Active Directory domain has a domain name. In your lab environment, the AD domain is named: thm.local. This is the internal domain namespace used by all users and computers in that AD environment. When I log in using RDP, Windows needs to know which domain the username belongs to. There are two accepted formats: "THM\phillip" or "phillip@thm.local".

Alternatively, you could enter "thm.local" and manually enter Phillips login credentials, which is what I did.
</blockquote>

<p align="left">
  <img src="images/active-directory-domain-structure-08.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 8</em>
</p>

In this lab environment, the Active Directory domain name "thm.local" is configured to resolve directly to the domain controller. This means that when I entered "thm.local" in the **Computer** field in Remote Desktop Connection, RDP was able to locate and connect to the domain controller successfully.

This is different from typical production environments where you usually RDP to a specific hostname or IP address. In many real-world setups, the domain name itself does not automatically resolve to a server for RDP.

This resolved correctly to the domain controller and brought me to the Windows login screen with the default blue background. From there, I logged in using Phillip’s domain credentials.

<p align="left">
  <img src="images/active-directory-domain-structure-09.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 9</em>
</p>

I was successfully able to access Phillip’s session on the machine, confirming that the credentials and domain login were working as expected. Once logged in, I had full access to his desktop environment and could proceed with testing the delegated permissions.

<p align="left">
  <img src="images/active-directory-domain-structure-10.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 10</em>
</p>

---

<h4>(Step 3) Testing Phillip's Credentials</h4>

---

**(Step 3-a)** Setting a new password for Sophie, as Phillip

Since Phillip does not have permission to open the ADUC GUI, I used PowerShell to perform the password reset. Using the `Set-ADAccountPassword cmdlet`, I reset Sophie’s password from the Sales department OU:

`Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose`

- `Set-ADAccountPassword` - Change or reset a user’s password in Active Directory.
- `sophie` - The user account we are resetting the password for.
- `-Reset` - Force a password reset (instead of the user changing it themselves).
- `-NewPassword` - The new password we want to assign to the account.
- `(Read-Host -AsSecureString -Prompt 'New Password')` - Pops up a secure password prompt so we can type the new password without showing it.
- `-Verbose` - Shows a confirmation message so we know the command worked.

<p align="left">
  <img src="images/active-directory-domain-structure-11.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 11</em>
</p>

The output confirmed the operation was made on the correct user of the Sales department OU:

`VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local"`

---

**(Step 3-b)** Forcing a password reset at next logon for Sophie

After completing the reset, I enforced a password change upon Sophie’s next logon to ensure secure credential practices: 

`Set-ADUser -ChangePasswordAtLogon -Identity sophie -Verbose`

<p align="left">
  <img src="images/active-directory-domain-structure-12.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 12</em>
</p>

At this point, Phillip had successfully been delegated password reset capabilities for users inside the Sales OU, demonstrating how targeted privilege delegation supports operational efficiency while preserving security boundaries.

---

### Findings / Analysis
Delegation allows organizations to split responsibility without granting full domain admin access. This reduces risk and supports scalable administration.

### What I Learned

I learned how role-based control and least privilege are implemented in real environments, matching what I studied in Security+ regarding privilege separation and insider threat mitigation.

</details>

---

## 5. Managing Workstations and Servers in AD

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To correctly organize computer objects in the domain so the right policies are applied to the right systems.

### Step-by-Step Walkthrough

I noticed that new systems appear in the default **Computers** container, which is not ideal for management. I created two new OUs: **Workstations** and **Servers**, then moved devices accordingly.

- I reviewed how new computers default into the **Computers** container.
- I created two new OUs: **Workstations** and **Servers**.
- I moved machines into their corresponding OUs based on role.

### Findings / Analysis
Grouping devices makes policy management predictable and easier to maintain. Servers require stricter controls than regular user workstations.

Separating servers from workstations allows different GPOs to apply depending on security requirements. Servers need stricter controls than user machines.

### What I Learned
I learned how system organization impacts security and manageability.

</details>

---

## 6. Group Policy (GPO) Configuration and Enforcement

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To understand how Group Policy enforces settings and security standards across the domain.

### Step-by-Step Walkthrough

I opened Group Policy Management and reviewed existing GPOs. I created a new GPO, linked it to an OU, and modified settings. I ran `gpupdate /force` on a workstation and verified the changes. I also used the Resultant Set of Policy tool to confirm which policies applied.

- I opened **Group Policy Management Console**.
- I created and linked a new Group Policy Object to a specific OU.
- I edited policy settings for that OU.
- I forced policy updates using `gpupdate /force`.
- I used Resultant Set of Policy (RSoP) to verify that the policy applied.

### Findings / Analysis
Group Policy ensures consistency, compliance, and baseline security across large numbers of systems. It is one of the strongest administrative tools in AD environments.

Group Policy allows configuration enforcement at scale. It ensures users and machines follow consistent security rules, which is something I repeatedly saw emphasized in Security+ for enterprise hardening.

### What I Learned
I learned how GPOs connect high‑level security policy to real system configuration.

</details>

---

## 7. Kerberos vs NTLM Authentication

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To understand how Active Directory handles authentication using Kerberos and how NTLM remains for legacy support.

### Findings / Analysis
- Kerberos uses encrypted tickets and is the default, secure authentication method.
- NTLM uses challenge‑response and is less secure, but still supported.
- Kerberos requires synchronized system time and functional DNS.

### What I Learned
This section reinforced Security+ topics about authentication, encryption, and replay attack prevention.

- Kerberos is the default domain authentication protocol and uses encrypted tickets.
- NTLM is older and less secure but remains for compatibility.
- Time synchronization is required for Kerberos to function.

This matched what I learned during Security+ when studying authentication, encryption, and replay attack prevention.

</details>

---

## 8. Trees, Forests, and Trust Relationships

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To understand how AD scales to large and multi-organization environments.

### Findings / Analysis
- A **Tree** is a grouping of domains in a shared namespace.
- A **Forest** is one or more trees connected through trust relationships.
- Trusts allow shared authentication across domains.

This explained how AD scales across large organizations.

### What I Learned
I learned how organizations expand AD across regions or subsidiaries without redesigning identity structures.

</details>

---

## 9. Conclusion and Final Reflection

<details>

<summary><b>(Click to expand)</b></summary>

### Summary
This lab allowed me to practice real administrative tasks in Active Directory while reinforcing Security+ identity management concepts. I learned how to organize users and devices, delegate privileges, apply Group Policy, and understand authentication protocols.

This lab has also helped me move from theoretical understanding to hands‑on use of Active Directory. I managed users, devices, OUs, delegated privileges, and configured GPOs. I also reinforced key identity and authentication concepts from my CompTIA Security+ studies.

### What I Learned
I gained practical experience working with AD infrastructure and now understand how identity, access control, and system configuration are enforced in enterprise environments.

- Active Directory centralizes authentication and identity management.
- OUs provide structure, groups provide permission control.
- Delegation supports least privilege.
- GPOs enforce consistent configuration and security.
- Kerberos provides secure authentication in modern Windows environments.

This lab strengthened my practical understanding of enterprise identity infrastructure and system administration workflows.

</details>
