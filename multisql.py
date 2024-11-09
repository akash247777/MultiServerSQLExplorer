# Import the tkinter module, which is used for creating the GUI application.
import tkinter as tk 
# Import specific components from tkinter to create enhanced GUI elements like ComboBoxes (ttk), 
# a file dialog to select files, and message boxes for alert messages.
from tkinter import ttk, filedialog, messagebox
# Import the hashlib library to use hashing algorithms, typically used here to hash passwords or sensitive data.
import hashlib
# Import pyodbc, a library that provides connectivity to SQL databases via ODBC drivers.
import pyodbc
# Import pandas, a powerful data manipulation library, which can handle data structures like DataFrames.
import pandas as pd
# Import BytesIO, which enables us to handle binary I/O, commonly used here for handling file-like byte streams.
from io import BytesIO
# Import the re module to use regular expressions, useful for pattern matching and data validation.
import re
# Import datetime to handle date and time information, likely used for timestamping logs.
from datetime import datetime
# Import os module to interact with the operating system, typically used for file handling and path management.
import os
# Import json library to work with JSON data, which is a common format for configuration and data exchange.
import json

# Define the file path where the application will store logs of user activity and queries.
LOG_FILE_PATH = "C:\\query_logs.xlsx"

# Define a constant for the maximum number of users that can be logged in to the application simultaneously.
MAX_ACTIVE_USERS = 2

# Specify the path for the JSON file storing user data (like usernames and passwords).
USER_DATA_FILE = 'C:\\Users\\APL41051\\user_data.json'


# Define the main class for the application that will handle the GUI and backend logic.
class SQLQueryApp:
    # Constructor method that initializes the application and sets up the main GUI elements.
    def __init__(self, master):
        # Save the reference to the main application window (master).
        self.master = master
        # Set the title of the main window to "SQL Query Application".
        self.master.title("SQL Query Application")
        # Define the dimensions of the main window to 800x600 pixels.
        self.master.geometry("800x600")

        # Initialize variables for tracking login status, current username, active users, and SQL credentials.
        self.logged_in = False  # Flag indicating if a user is currently logged in.
        self.username = None  # Placeholder for the username of the currently logged-in user.
        self.active_users = []  # List to store the usernames of currently active users.
        self.sql_server_credentials = None  # Placeholder for SQL server login credentials.
        self.default_database = "POSDBIR"  # Define the default database to use in SQL queries.

        # Call the function to create GUI components for the application.
        self.create_widgets()
        # Display the login frame first for user authentication.
        self.show_login_frame()


    # Defines a method named 'create_widgets' which is part of a class (indicated by 'elf')
   def create_widgets(self):
       # Initializes a ttk Notebook widget (for tabbed interface) as an attribute of the class instance
       self.notebook = ttk.Notebook(self.master)
    
       # Packs the notebook into its parent widget (self.master), allowing it to expand in both directions
       self.notebook.pack(fill=tk.BOTH, expand=True)

       # Creates a new frame for the login interface as a tab within the notebook
       self.login_frame = ttk.Frame(self.notebook)
    
       # Creates a new frame for the credentials interface as a separate tab within the notebook
       self.credentials_frame = ttk.Frame(self.notebook)
    
       # Creates a new frame for the main application interface as another tab within the notebook
       self.app_frame = ttk.Frame(self.notebook)

       # Calls a method to create and configure widgets specifically for the login frame
       self.create_login_widgets()
    
       # Calls a method to create and configure widgets specifically for the credentials frame
       self.create_credentials_widgets()
    
       # Calls a method to create and configure widgets specifically for the main application frame
       self.create_app_widgets()

    def show_login_frame(self):
    # Check if the login frame is not already a tab in the notebook
        if self.login_frame not in self.notebook.tabs():
        # Add the login frame to the notebook with the label "Login"
           self.notebook.add(self.login_frame, text="Login")
    # Set focus to the login frame tab in the notebook
        self.notebook.select(self.login_frame)

    def show_credentials_frame(self):
    # Check if the credentials frame is not already a tab in the notebook
        if self.credentials_frame not in self.notebook.tabs():
        # Add the credentials frame to the notebook with the label "SQL Server Credentials"
           self.notebook.add(self.credentials_frame, text="SQL Server Credentials")
    # Set focus to the credentials frame tab in the notebook
        self.notebook.select(self.credentials_frame)


    def show_app_frame(self):
    # Check if the app frame is not already a tab in the notebook
        if self.app_frame not in self.notebook.tabs():
        # Add the app frame to the notebook with the label "SQL Queries"
           self.notebook.add(self.app_frame, text="SQL Queries")
    # Set focus to the app frame tab in the notebook
        self.notebook.select(self.app_frame)
   

    def create_login_widgets(self):
    # Create and add a label for the username field in the login frame
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
    
    # Create an entry widget for the username and add it to the login frame
        self.login_username = ttk.Entry(self.login_frame)
        self.login_username.pack(pady=5)

    # Create and add a label for the password field in the login frame
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
    
    # Create an entry widget for the password with masked input and add it to the login frame
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.pack(pady=5)

        ttk.Button(self.login_frame, text="Sign In", command=self.login).pack(pady=10)
    
    def create_credentials_widgets(self):
    # Create and add a label for the SQL Server User ID field in the credentials frame
        ttk.Label(self.credentials_frame, text="SQL Server User ID:").pack(pady=5)
    
    # Create an entry widget for the SQL Server User ID and add it to the credentials frame
        self.sql_user_id = ttk.Entry(self.credentials_frame)
        self.sql_user_id.pack(pady=5)

    # Create and add a label for the SQL Server Password field in the credentials frame
        ttk.Label(self.credentials_frame, text="SQL Server Password:").pack(pady=5)
    
    # Create an entry widget for the SQL Server Password with masked input and add it to the credentials frame
        self.sql_password = ttk.Entry(self.credentials_frame, show="*")
        self.sql_password.pack(pady=5)

    # Create a submit button for submitting the credentials and add it to the credentials frame
    # When clicked, it triggers the submit_credentials method
        ttk.Button(self.credentials_frame, text="Submit", command=self.submit_credentials).pack(pady=10)


        
   def create_app_widgets(self):
    # Create a frame for placing the Logout and Download buttons at the top-right corner of the app frame
       self.top_right_frame = ttk.Frame(self.app_frame)
       self.top_right_frame.pack(side="top", anchor="ne", padx=10, pady=10)

    # Add the Logout button to the top-right frame with a command to trigger the logout function
       ttk.Button(self.top_right_frame, text="Logout", command=self.logout).pack(side="right", padx=5)
    
    # Add the Download Results button to the top-right frame with a command to trigger the download_results function
       ttk.Button(self.top_right_frame, text="Download Results", command=self.download_results).pack(side="right", padx=5)

    # Create a dropdown (combobox) to choose a series, bind it to a variable, and add it to the app frame
       self.series_var = tk.StringVar()
       ttk.Label(self.app_frame, text="Choose a series:").pack(pady=5)
       ttk.Combobox(self.app_frame, textvariable=self.series_var, values=["16", "28"]).pack(pady=5)

    # Add a button to upload an Excel file, triggering the upload_file function on click
       ttk.Button(self.app_frame, text="Upload Excel file", command=self.upload_file).pack(pady=10)

    # Create a listbox for displaying a list of servers, specifying dimensions, and add it to the app frame
       self.server_listbox = tk.Listbox(self.app_frame, width=30, height=10)
       self.server_listbox.pack(pady=10)

    # Create a label and text input area for entering SQL queries in the app frame
       ttk.Label(self.app_frame, text="Enter SQL Query:").pack(pady=5)
       self.query_text = tk.Text(self.app_frame, height=4)
       self.query_text.pack(pady=5)

    # Add an Execute Query button that triggers the execute_query function when clicked
       ttk.Button(self.app_frame, text="Execute Query", command=self.execute_query).pack(pady=10)

    # Create a text widget for displaying query results and add it to the app frame
       self.results_text = tk.Text(self.app_frame, height=10)
       self.results_text.pack(pady=10)
 

         
    
   def hash_password(self, password):
    # Hash the input password using SHA-256 and return the hexadecimal digest
       return hashlib.sha256(str.encode(password)).hexdigest()

   def log_query_to_excel(self, username, query):
    # Create a log entry dictionary with the username, query, and current timestamp
       log_entry = {
          "Username": username,
          "Query": query,
          "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
       }
    
    # Convert the log entry dictionary to a DataFrame for easier Excel writing
       log_df = pd.DataFrame([log_entry])

    # Check if the log file already exists
       if os.path.exists(LOG_FILE_PATH):
        # If the file exists, open it in append mode and write the log entry without headers,
        # positioning the new entry below existing ones in 'Sheet1'
          with pd.ExcelWriter(LOG_FILE_PATH, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
            log_df.to_excel(writer, index=False, header=False, startrow=writer.sheets['Sheet1'].max_row)
      else:
        # If the log file doesn't exist, create it and write the log entry with headers
          log_df.to_excel(LOG_FILE_PATH, index=False)

   def load_user_data():
    try:
        # Check if the user data file exists; show an error message if it doesn't and return None
        if not os.path.exists(USER_DATA_FILE):
            messagebox.showerror("Error", f"User data file not found at {USER_DATA_FILE}")
            return None

        # Check if the file has read permissions; show an error if it doesn't and return None
        if not os.access(USER_DATA_FILE, os.R_OK):
            messagebox.showerror("Error", f"No read permission for {USER_DATA_FILE}")
            return None

        # Open the file in read mode and load the JSON data, returning it as a dictionary or list
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    
    # Handle JSON decoding errors and show an error message if the JSON format is invalid
    except json.JSONDecodeError:
        messagebox.showerror("Error", f"Invalid JSON format in {USER_DATA_FILE}")
        return None
    
    # Handle other I/O errors, display the error message, and return None
    except IOError as e:
        messagebox.showerror("Error", f"Error reading file: {e}")
        return None

    
    def login(self):
    # Retrieve the entered username and password from the login fields
        username = self.login_username.get()
        password = self.login_password.get()

    # Check if the maximum number of active users has been reached
        if len(self.active_users) >= MAX_ACTIVE_USERS:
           messagebox.showwarning("Warning", f"The app is currently in use by {MAX_ACTIVE_USERS} users. Please try again later.")
           return

    # Proceed only if both username and password fields are filled
    if username and password:
        # Load user data from the data file; return if loading fails
           user_data = self.load_user_data()
           if user_data is None:
              return
            
        # Check if the entered credentials match any valid user's credentials in user data
           valid_user = any(
               cred["username"] == username and cred["password"] == password 
               for cred in user_data["credentials"]
        )
        
        # If credentials are valid, check if the user is already logged in
        if valid_user:
            if username in self.active_users:
                messagebox.showerror("Error", "This user is already logged in.")
                return
            
            # Mark the login as successful, update active users, and save the username
            self.logged_in = True
            self.active_users.append(username)
            self.username = username
            messagebox.showinfo("Success", "Login successful!")
            
            # Show the credentials frame for further actions
            self.show_credentials_frame()
        else:
            # Show an error if the credentials are invalid
            messagebox.showerror("Error", "Invalid username or password.")
    else:
        # Show an error if either the username or password is missing
        messagebox.showerror("Error", "Please enter both username and password.")

    
    def submit_credentials(self):
    # Get the entered SQL Server User ID and Password from the respective input fields
        user_id = self.sql_user_id.get()
        password = self.sql_password.get()

    # Check if both SQL Server User ID and Password are provided
       if user_id and password:
        # Store the credentials in a dictionary for later use (e.g., for connecting to the server)
          self.sql_server_credentials = {
            "database": self.default_database,  # The default database associated with these credentials
            "user_id": user_id,                 # SQL Server User ID
            "password": password                # SQL Server Password
          }
         
        # Show a success message that the credentials have been submitted
          messagebox.showinfo("Success", "SQL Server credentials submitted successfully!")
        
        # Show the app frame, which presumably allows the user to interact with the app further
          self.show_app_frame()
      else:
        # Show an error message if either the User ID or Password is missing
         messagebox.showerror("Error", "Please enter both SQL Server User ID and Password.")

    
    def logout(self):
    # Clear session data to log the user out
        self.logged_in = False  # Set the logged-in status to False
        if self.username in self.active_users:  # Remove the user from the active users list if they are in it
            self.active_users.remove(self.username)
        self.username = None  # Reset the username to None
        self.sql_server_credentials = None  # Clear stored SQL server credentials

    # Clear all input fields to remove any sensitive data
        self.login_username.delete(0, tk.END)  # Clear the login username field
        self.login_password.delete(0, tk.END)  # Clear the login password field
        self.sql_user_id.delete(0, tk.END)     # Clear the SQL user ID field
        self.sql_password.delete(0, tk.END)    # Clear the SQL password field
        self.query_text.delete("1.0", tk.END)  # Clear the SQL query text field
        self.results_text.delete("1.0", tk.END)  # Clear the results text field

    # Forget all tabs except the login tab to reset the user interface
        for tab in self.notebook.tabs():
           if tab != str(self.login_frame):  # Only keep the login tab visible
               self.notebook.forget(tab)  # Forget other tabs (i.e., remove them from the UI)

    # Ensure the login tab is shown and selected
        if self.login_frame not in self.notebook.tabs():
            self.notebook.add(self.login_frame, text="Login")  # Add the login tab if it's not already there
        self.notebook.select(self.login_frame)  # Select the login tab to show it

    # Show a message indicating that the user has logged out successfully
        messagebox.showinfo("Success", "Logged out successfully!")


    def upload_file(self):
    # Open a file dialog to let the user choose an Excel file
        file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    
    # Proceed if a file is selected
        if file_path:
           try:
            # Attempt to read the selected Excel file into a DataFrame using pandas
               df = pd.read_excel(file_path)
            
            # Check if the 'Server' column exists in the DataFrame
               if 'Server' in df.columns:
                # Clear any existing entries in the server listbox
                    self.server_listbox.delete(0, tk.END)
                
                # Insert each server from the 'Server' column into the listbox
                    for server in df['Server']:
                        self.server_listbox.insert(tk.END, server)
               else:
                # Show an error if the 'Server' column is missing from the file
                    messagebox.showerror("Error", "The uploaded file does not contain a 'Server' column.")
           except Exception as e:
            # Show an error message if there is any issue reading the Excel file
                  messagebox.showerror("Error", f"Error reading Excel file: {e}")

    def validate_ip(self, ip):
    # Check if the IP address format matches the pattern: 1-3 digits, followed by three groups of 1-3 digits separated by dots
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        # Return an error message if the format is incorrect (contains characters or special symbols)
            return "Invalid format: characters or special symbols are not allowed."
    
    # Split the IP address into its individual octets (by the dot separator)
        octets = ip.split('.')
    
    # Check if each octet is a valid number between 0 and 255
        for octet in octets:
            if not (0 <= int(octet) <= 255):  # Ensure the integer value of the octet is within the range 0-255
            # Return an error message if any octet is outside the valid range
                 return "Invalid format: each octet should be between 0 and 255."
    
    # If no errors were found, return None (indicating the IP address is valid)
        return None


    def connect_and_query(self, server, query):
        try:
        # Establish a connection to the SQL Server using the credentials provided
             connection = pyodbc.connect(
                   f'DRIVER={{ODBC Driver 17 for SQL Server}};'  # Specify the ODBC driver for SQL Server
                   f'SERVER={server};'                          # Use the provided server address
                   f'DATABASE={self.sql_server_credentials["database"]};'  # Use the default database from credentials
                   f'UID={self.sql_server_credentials["user_id"]};'         # Use the user ID from credentials
                   f'PWD={self.sql_server_credentials["password"]};'         # Use the password from credentials
              )
        
        # Show a success message if connection is successful
              messagebox.showinfo("Success", f"Connected to SQL Server on {server} successfully!")

        # Create a cursor object to interact with the database
              cursor = connection.cursor()
        
        # Execute the provided SQL query
              cursor.execute(query)

        # If the query is a SELECT statement, fetch the results
              if query.lower().startswith('select'):
                  rows = cursor.fetchall()  # Fetch all rows returned by the query
                  columns = [column[0] for column in cursor.description]  # Get column names from the cursor description
            
            # If results are returned, convert the rows to a pandas DataFrame
                  if rows:
                      return pd.DataFrame.from_records(rows, columns=columns)
                  else:
                # If no results are returned, show a warning message and return an empty DataFrame
                       messagebox.showwarning("Warning", f"No results returned from {server}.")
                       return pd.DataFrame()

        except pyodbc.Error as e:
        # If an error occurs while connecting or querying, show an error message and return an empty DataFrame
                 messagebox.showerror("Error", f"Error connecting to SQL Server on {server}: {e}")
                 return pd.DataFrame()

        finally:
        # In the finally block, ensure that the cursor and connection are closed properly
            try:
                 if cursor:  # If the cursor was created, close it
                    cursor.close()
                 if connection:  # If the connection was established, close it
                    connection.close()
            # Inform the user that the connection is closed
                 messagebox.showinfo("Info", f"Connection to {server} closed.")
           except:
                pass  # If an error occurs during cleanup, just pass (no action needed)


    def execute_query(self):
    # Get the query entered by the user from the Text widget
        query = self.query_text.get("1.0", tk.END).strip()

    # Check if the query is empty, and display an error message if so
        if not query:
            messagebox.showerror("Error", "Please enter a query.")
            return

    # Log the query execution to an Excel file for tracking
       self.log_query_to_excel(self.username, query)

    # Initialize an empty DataFrame to store all the results from different servers
       all_results = pd.DataFrame()

    # Get the selected series (e.g., "16" or "28") from the combo box
       series_choice = self.series_var.get()

    # Loop through each server in the server listbox
    for server in self.server_listbox.get(0, tk.END):
        # Construct the primary IP address by replacing part of the server string based on the series choice
           primary_ip = f"10.{series_choice}." + ".".join(server.split('.')[2:])
        
        # Display an informational message about the IP being used to connect
           messagebox.showinfo("Info", f"Attempting to connect to: {primary_ip}")
        
        # Try connecting to the server and executing the query
          result = self.connect_and_query(primary_ip, query)

        # If no results were returned, try connecting to an alternate IP address based on the other series
          if result.empty:
            # Switch the series to the alternate series (either "28" or "16")
            alternate_series = "28" if series_choice == "16" else "16"
            # Construct the alternate IP address using the alternate series
            alternate_ip = f"10.{alternate_series}." + ".".join(server.split('.')[2:])
            
            # Display an informational message about the alternate IP being used
            messagebox.showinfo("Info", f"Attempting to connect to alternate IP: {alternate_ip}")
            
            # Try connecting to the alternate IP address
            result = self.connect_and_query(alternate_ip, query)

        # If results were successfully returned from the server (either primary or alternate IP), concatenate them
        if not result.empty:
            all_results = pd.concat([all_results, result], ignore_index=True)
        else:
            # If no results or a connection error occurred, show an error message and move on to the next server
            messagebox.showerror("Error", f"No results or connection error for {server}. Moving to next server...")

    # If there are any results, display them in the results text box
    if not all_results.empty:
        # Clear the previous results in the Text widget
        self.results_text.delete("1.0", tk.END)
        # Insert the new results into the Text widget
        self.results_text.insert(tk.END, all_results.to_string(index=False))
    else:
        # If no results were returned from any server, show an informational message
        messagebox.showinfo("Info", "No results from any server.")


    def download_results(self):
    # Get the query results from the results_text widget
        results = self.results_text.get("1.0", tk.END)

    # Check if there are no results to download and display a warning message
       if not results.strip():
           messagebox.showwarning("Warning", "No results to download.")
           return

    # Convert the results (which are in plain text) to a pandas DataFrame
    # Use BytesIO to handle the results as a byte stream and read them as a CSV with whitespace separation
       df = pd.read_csv(BytesIO(results.encode()), sep=r'\s+')

    # Define the default download folder (user's Downloads directory)
       download_folder = os.path.join(os.path.expanduser("~"), "Downloads")

    # Define the full file path where the results will be saved
       file_path = os.path.join(download_folder, "query_results.xlsx")

    # Try saving the results to an Excel file in the default download folder
       try:
           df.to_excel(file_path, index=False)  # Save the DataFrame to an Excel file without the index column
           messagebox.showinfo("Success", f"Results downloaded successfully to {file_path}!")  # Show success message
       except Exception as e:
        # If there is an error during the file saving process, show an error message
           messagebox.showerror("Error", f"Failed to download results: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLQueryApp(root)
    root.mainloop()
