# Import the libraries required for the program

import bcrypt # encryption library https://pypi.org/project/bcrypt/
import sqlite3 #standard library included with python installation
import pyinputplus as pyip # input validation library https://pypi.org/project/PyInputPlus/
from password_validator import PasswordValidator #validates passwords according to a password policy https://pypi.org/project/password-validator/
import os.path # standard library included with python installation
import pyotp # OTP generation and verification library https://pypi.org/project/pyotp/

totp = pyotp.TOTP("base32secret3232", digits=6, interval=30) # set OTP parameters

####Define all the functions used in the program###



def dbsetup(): #creates and populates initial database.
    
    #check to see if the patient database has already been created to avoid 'table patients already exists' error
    
    if os.path.exists('patient.db') == True:
        return
    
    
    #list containing previous registered patients to pre-populate database for testing

    patient1_list=[1, "Claire", "Stevens", "claire@somemail.com", "12345678", b'$2b$12$AUetMCgSXwWWmnbkiEqleOlcIR0Si2VeDAKyPH4quXyuj/PMYh1vO']
    patient2_list=[2, "Fred", "Smith", "fred@somemail.com", "87656721", b'$2b$12$GV8nHPadj3nDaYukxiEEp.KXCwFNJksz4SM74zcmqme9Jgeb2QhMq']

    conn = sqlite3.connect('patient.db') #('patient.db') create database name ----- use :memory: for testing
    c=conn.cursor() #open a connection

    #Create the database structure

    c.execute("""CREATE TABLE patients (
                patient_id int,
                first_name text,
                last_name text,
                email_address text,
                mobile_number text,
                pwd_hash text
            )""")

    #Populate the database with patient data from the list

    c.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?)", patient1_list)
    c.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?)", patient2_list)
    conn.commit() #commit changes
    conn.close #close connection
    

def patient_menu():
    print("\n\nYou have successfully logged in to the \nQueens Medical Centre Appointment Booking System")
    print("\nYour unique patient ID number is: ",id)
    
def password_check(): #This function checks that the password chosen matches the password policy

    # Create a policy
    schema = PasswordValidator()

    # Add properties to it
    schema\
    .min(8)\
    .max(16)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .has().no().spaces()\
    .has().symbols()\

#The while loop below instructs the user to choose a password and validates it against the password policy
#If the chosen password passes validation, it returns the password back to the registration function register()
    
    while True:
        print("Choose a password")
        print("Min 8 characters, max 16 characters")
        print("Must contain at least:")
        print("One upper case character")
        print("One lower case character")
        print("One number")
        print("One symbol character")
        password=input('Enter a password')
        if (schema.validate(password))==True:
            return(password)
        else:
            print("Invalid password")
            
def add_patient(new_first, new_last, new_mobile, new_email, new_hash ): #Checks if patient is already registered (checks email address) and arites new record if not

    conn = sqlite3.connect('patient.db')
    c=conn.cursor() #open connection
    c.execute("SELECT rowid FROM patients WHERE email_address = ?", (new_email,)) #query the DB on the new email address
    result=c.fetchone() #this returns None if the email doesn't exist
    if result==None:
        c.execute("SELECT COUNT(*) FROM patients") #query number of rows in table as this acts as the patient ID
        count=c.fetchone()
        patient_id=(count[0])+1 #increment patient id before adding record.
        c.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?)",(patient_id, new_first, new_last, new_email, new_mobile, new_hash))
        conn.commit()
        
        ### Used for testing purposes only to check correct addition of record to database ###
        #c.execute("SELECT * FROM patients")
        #check=c.fetchall()
        #print("\n",check)
        ################################### End of testing code ##############################
        
        conn.close()
        print("\n You have successefully registered on the system\n\n")
        menu()
    else:
        conn.close()
        print("\nYou are already registered! Please Login.\n")
        menu()
              

    
def login_check(email, pwd): #check email and password for user log in
    conn = sqlite3.connect('patient.db')
    c=conn.cursor()
    c.execute("SELECT pwd_hash, patient_id FROM patients WHERE email_address=?",(email,)) #fetch the password hashes related to the email address from the database
    result=(c.fetchall())
    if result!=[]: #check to see if the result list contains data
        pwd=pwd.encode() #encode the entered password
        hashed=result[0][0] #extract the stored password hash for the entered email address from the list
        global id #declare global variable to store patient id and access outside of the function
        id=result[0][1]
        check=bcrypt.checkpw(pwd, hashed) #compare the password hashes returns True if they are the same
        if check==True:
            mfa_check()
            
        else:
            print("\nemail / password incorrect.\n")
            login()
    else:
        print("\nemail / password incorrect.\n")
        login()
        

def mfa_check(): #creates and verifies an OTP for login
    
    print("\nYour OTP code is: ",totp.now())
    code=input("\nEnter your OTP here: ")
    print(totp.verify(code))
    if totp.verify(code) == True:
        patient_menu()
        
    else:
        print("\nCode incorrect\n")
        login()
    
    
def welcome(): #Display the main menu for patient login / registration
    print("Welcome to the Queens Medical Centre")
    print("    Appointment Booking System")
    print("\n        Menu")
    print("\n 1 - Login\n 2 - Register")

def login(): #define login process function
    print("Welcome to the Queens Medical Centre")
    print("    Appointment Booking System")
    print("\nEnter your email address and password to log in")
    email=input("\nEmail address: ")
    pwd=input("Password: ")
    login_check(email,pwd)
    
def register(): # define registration process
    print("Welcome to the Queens Medical Centre")
    print("    Appointment Booking System")
    print("\nNew patient Registration Screen")
    print("\nComplete your information as requested below:")
    
    new_first=pyip.inputStr(prompt='\nEnter your first name: ')
    new_last=pyip.inputStr(prompt='Enter your last name: ')
    new_email=pyip.inputEmail(prompt='Enter your email address: ')
    new_mobile=pyip.inputStr(prompt='Enter your mobile number: ')
    
    new_pass=password_check() #call the function which requests and validates chosen passwords and returns the validated password
    new_pass = new_pass.encode()
    salt = bcrypt.gensalt() # generate password salt
    new_hash = bcrypt.hashpw(new_pass,salt) # create the new salted password hash
    
    add_patient(new_first, new_last, new_mobile, new_email, new_hash) # call function to add new record
    
    


def menu(): #Check validity of menu choice
    welcome()
    while True:
        choice = input("\nEnter 1 or 2 ") # variable 'choice' holds the user menu option selected
        if choice == "1":
            login()
            break
        elif choice == "2":
            register()
            break
        else:
            print("Invalid option")

dbsetup()
menu()