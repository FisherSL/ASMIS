# ASMIS

# Web-based Appointment Scheduling and Management Information System (ASMIS)

Please feel free to comment on my code and approach. Being a beginner coder, I am certain there are more pythonic ways of doing things.

Description

This is a basic, working prototype of an ASMIS submitted as part of the final assessment for the Launching into Cybersecurity Model of the Masters in Cybersecurity, at the University of Essex Online. It demonstrates the implementation of some mitigations against possible attacks by threat actors to access sensitive personal data which would be stored in such a system.

The security mitigations chosen to be demonstrated are:

1.    Salting and hashing of passwords; passwords must never be stored as plain text.

2.    Application of a strict password policy when registering on the system to ensure good quality passwords are chosen by users. In this case, the requirement is set at: length between 8 & 16 characters, at least one upper case, one lower case, one number, one special character and no spaces.

3.    Two factor authentication: after providing a verified email address and password combination, the user is sent a time critical OTP which they must enter before it expires.

System Requirements and dependencies.

The prototype is written entirely in the latest stable version of Python 3 (currently version 3.11.1). In addition to the standard libraries, the following are also required:

Bcrypt 4.0.1  https://pypi.org/project/bcrypt/

Used to salt and hash passwords for before storing and comparing password hashes on login.

PyInputPlus 0.2.12 https://pypi.org/project/PyInputPlus/

Advanced user input validation when a user is registering.

Password-validator 1.0 https://pypi.org/project/password-validator/

Enables application of a strict password policy.

Pyotp 2.7.0 https://pypi.org/project/pyotp/

Creation and validation of time limited OTPs for 2 factor authentication.

Using the system

Start the program by running main.py after installing all the required libraries.

There are two patient user accounts which are created in the database when the program is executed. Each patient record contains a key value of patient_id which is stored as an integer. These act as demo accounts for testing purposes. The login details for these accounts are:

claire@somemail.com         Password1                Patient id=1 (key value)

fred@somemail.com           Password2                Patient id=2 (key value)

These passwords were salted and hashed using the bcrypt library and hard coded into a list, along with the other fields required for each record, which is then used to populate the initial database.

Limitations of the system.

The system is designed for demonstration of the aforementioned security mitigations only and is not representative of all the mitigations which should be included into such a system. A selection of these assumptions / limitations is outlined below:

1.    The sqlite3 database file is created on first running of the system and stored in the same folder as the main program. In practice, the database file should be stored on a secure server.

2.    Input validation and processing is only used where essential for the purposes of demonstrating the chosen mitigations. For example, name fields only test for string entry, not a capitalized first letter. Any string is accepted as a telephone number. Email addresses are not checked for blacklisted or active domains.

3.    When entering passwords, it would be desirable to implement password cloaking to prevent eavesdropping.

4.    Repeated login failures should result in that account being locked along with the incident being logged for further investigation.

5.    Password confirmation would be desirable when selecting a password during the registration process to prevent issues with typos during password entry.

6.    During 2FA, an OTP is displayed on the screen for the user to confirm in the system. In practice, this would be sent to a different device such as a mobile phone.

7.    A delay following unsuccessful login or user attempts would help mitigate against brute force and spamming attacks.
