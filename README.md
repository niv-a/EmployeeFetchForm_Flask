Project Name
Instant Responce System - Get the employee details on a click

Description
This application consists of two main parts: the login and signup page, and the search form. The project utilizes Flask as the backend framework and incorporates a pre-designed template provided by the NIC (National Informatics Centre) website.

First Part: Login and Signup
The first part of the application focuses on user authentication and registration. The backend is built using Flask, while the frontend uses the provided NIC template. Various checks and validations have been implemented to ensure secure and reliable user signups and logins.

Signup Process
During the signup process, the application verifies the email address provided by the user. An email verification link is sent to the provided email address. The backend logic handles the verification process and updates the database accordingly. User details, such as email, are stored in a 'users' table in the PostgresSQL database. The structure and attributes of the 'users' table are defined in the 'models.py' file of the application. It is important to note that the email field serves as the unique username for each user.

Login Process
For logging in, the application employs an OTP (One-Time Password) system. Upon entering the correct credentials, including the email and OTP received via email, the user is redirected to the second part of the application, the search form. The user information is securely stored in the PostgresSQL database.

Second Part: Search Form
The second part of the application focuses on displaying data fetched from the PostgresSQL database and presenting it in a table format. Flask and the Jinja template engine are used to implement this feature.

Search Functionality
The search form allows users to input their desired search criteria. The application then queries the database based on these criteria and displays the matching results in a table. This functionality enables users to easily access and analyze the data stored in the database.

Requirements
To run this application locally, you need to have the following software installed:

Python 3.x
Flask framework
PostgresSQL database

Work done till, implementing otp and email verification on login and signup respt. The integration of the two files have been done and run successfully. The fields where the credential for the mail service, otp service, database connection and other spots wherever required has been mention with the comment "#enter" and additional info is also given in the comment as required.
Thank You.
