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
    # Add only the login frame if it is not already in the notebook
        if self.login_frame not in self.notebook.tabs():
            self.notebook.add(self.login_frame, text="Login")
    # Select the login frame
        self.notebook.select(self.login_frame)

    def show_credentials_frame(self):
        # Add only the credentials frame if it is not already in the notebook
        if self.credentials_frame not in self.notebook.tabs():
            self.notebook.add(self.credentials_frame, text="SQL Server Credentials")
    # Select the credentials frame
        self.notebook.select(self.credentials_frame)

    def show_app_frame(self):
        if self.app_frame not in self.notebook.tabs():
           self.notebook.add(self.app_frame, text="SQL Queries")
    # Select the app frame
        self.notebook.select(self.app_frame)    

    def create_login_widgets(self):
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.login_username = ttk.Entry(self.login_frame)
        self.login_username.pack(pady=5)

        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.pack(pady=5)

        ttk.Button(self.login_frame, text="Sign In", command=self.login).pack(pady=10)
    
    def create_credentials_widgets(self):
        ttk.Label(self.credentials_frame, text="SQL Server User ID:").pack(pady=5)
        self.sql_user_id = ttk.Entry(self.credentials_frame)
        self.sql_user_id.pack(pady=5)

        ttk.Label(self.credentials_frame, text="SQL Server Password:").pack(pady=5)
        self.sql_password = ttk.Entry(self.credentials_frame, show="*")
        self.sql_password.pack(pady=5)

        ttk.Button(self.credentials_frame, text="Submit", command=self.submit_credentials).pack(pady=10)

        
    def create_app_widgets(self):
        
     # Create a frame for the top-right buttons (Logout and Download)
        self.top_right_frame = ttk.Frame(self.app_frame)
        self.top_right_frame.pack(side="top", anchor="ne", padx=10, pady=10)

        # Add the Logout and Download buttons to the top-right frame
        ttk.Button(self.top_right_frame, text="Logout", command=self.logout).pack(side="right", padx=5)
        ttk.Button(self.top_right_frame, text="Download Results", command=self.download_results).pack(side="right", padx=5)

        # Rest of the app frame widgets
        self.series_var = tk.StringVar()
        ttk.Label(self.app_frame, text="Choose a series:").pack(pady=5)
        ttk.Combobox(self.app_frame, textvariable=self.series_var, values=["16", "28"]).pack(pady=5)

        ttk.Button(self.app_frame, text="Upload Excel file", command=self.upload_file).pack(pady=10)

        self.server_listbox = tk.Listbox(self.app_frame, width=30, height=10)
        self.server_listbox.pack(pady=10)

        ttk.Label(self.app_frame, text="Enter SQL Query:").pack(pady=5)
        self.query_text = tk.Text(self.app_frame, height=4)
        self.query_text.pack(pady=5)

        # Add the Execute Query button
        ttk.Button(self.app_frame, text="Execute Query", command=self.execute_query).pack(pady=10)

        self.results_text = tk.Text(self.app_frame, height=10)
        self.results_text.pack(pady=10)

         
    
    def hash_password(self, password):
        return hashlib.sha256(str.encode(password)).hexdigest()

    def log_query_to_excel(self, username, query):
        log_entry = {
            "Username": username,
            "Query": query,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        log_df = pd.DataFrame([log_entry])

        if os.path.exists(LOG_FILE_PATH):
            with pd.ExcelWriter(LOG_FILE_PATH, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
                log_df.to_excel(writer, index=False, header=False, startrow=writer.sheets['Sheet1'].max_row)
        else:
            log_df.to_excel(LOG_FILE_PATH, index=False)
    @staticmethod
    def load_user_data():
        try:
            if not os.path.exists(USER_DATA_FILE):
                messagebox.showerror("Error", f"User data file not found at {USER_DATA_FILE}")
                return None

            if not os.access(USER_DATA_FILE, os.R_OK):
                messagebox.showerror("Error", f"No read permission for {USER_DATA_FILE}")
                return None

            with open(USER_DATA_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            messagebox.showerror("Error", f"Invalid JSON format in {USER_DATA_FILE}")
            return None
        except IOError as e:
            messagebox.showerror("Error", f"Error reading file: {e}")
            return None
    
    def login(self):
        username = self.login_username.get()
        password = self.login_password.get()

        if len(self.active_users) >= MAX_ACTIVE_USERS:
            messagebox.showwarning("Warning", f"The app is currently in use by {MAX_ACTIVE_USERS} users. Please try again later.")
            return

        if username and password:
            user_data = self.load_user_data()
            if user_data is None:
                return
                
            # Check credentials against the list of valid users
            valid_user = any(
                cred["username"] == username and cred["password"] == password 
                for cred in user_data["credentials"]
            )
            
            if valid_user:
                if username in self.active_users:
                    messagebox.showerror("Error", "This user is already logged in.")
                    return
                    
                self.logged_in = True
                self.active_users.append(username)
                self.username = username
                messagebox.showinfo("Success", "Login successful!")
                self.show_credentials_frame()
            else:
                messagebox.showerror("Error", "Invalid username or password.")
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    
    def submit_credentials(self):
        user_id = self.sql_user_id.get()
        password = self.sql_password.get()

        if user_id and password:
            self.sql_server_credentials = {
                "database": self.default_database,
                "user_id": user_id,
                "password": password
            }
            messagebox.showinfo("Success", "SQL Server credentials submitted successfully!")
            self.show_app_frame()
        else:
            messagebox.showerror("Error", "Please enter both SQL Server User ID and Password.")
    
    def logout(self):
    # Clear session data
        self.logged_in = False
        if self.username in self.active_users:
           self.active_users.remove(self.username)
        self.username = None
        self.sql_server_credentials = None

    # Clear input fields
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.sql_user_id.delete(0, tk.END)
        self.sql_password.delete(0, tk.END)
        self.query_text.delete("1.0", tk.END)
        self.results_text.delete("1.0", tk.END)

    # Forget all tabs except login
        for tab in self.notebook.tabs():
           if tab != str(self.login_frame):  # Only keep the login tab
             self.notebook.forget(tab)

    # Ensure login tab is shown
        if self.login_frame not in self.notebook.tabs():
           self.notebook.add(self.login_frame, text="Login")
        self.notebook.select(self.login_frame)

        messagebox.showinfo("Success", "Logged out successfully!")


    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
        if file_path:
            try:
                df = pd.read_excel(file_path)
                if 'Server' in df.columns:
                    self.server_listbox.delete(0, tk.END)
                    for server in df['Server']:
                        self.server_listbox.insert(tk.END, server)
                else:
                    messagebox.showerror("Error", "The uploaded file does not contain a 'Server' column.")
            except Exception as e:
                messagebox.showerror("Error", f"Error reading Excel file: {e}")

    def validate_ip(self, ip):
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return "Invalid format: characters or special symbols are not allowed."
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return "Invalid format: each octet should be between 0 and 255."
        return None

    def connect_and_query(self, server, query):
        try:
            connection = pyodbc.connect(
                f'DRIVER={{ODBC Driver 17 for SQL Server}};'
                f'SERVER={server};'
                f'DATABASE={self.sql_server_credentials["database"]};'
                f'UID={self.sql_server_credentials["user_id"]};'
                f'PWD={self.sql_server_credentials["password"]};'
            )
            messagebox.showinfo("Success", f"Connected to SQL Server on {server} successfully!")

            cursor = connection.cursor()
            cursor.execute(query)

            if query.lower().startswith('select'):
                rows = cursor.fetchall()
                columns = [column[0] for column in cursor.description]
                if rows:
                    return pd.DataFrame.from_records(rows, columns=columns)
                else:
                    messagebox.showwarning("Warning", f"No results returned from {server}.")
                    return pd.DataFrame()

        except pyodbc.Error as e:
            messagebox.showerror("Error", f"Error connecting to SQL Server on {server}: {e}")
            return pd.DataFrame()

        finally:
            try:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()
                messagebox.showinfo("Info", f"Connection to {server} closed.")
            except:
                pass

    def execute_query(self):
        query = self.query_text.get("1.0", tk.END).strip()
        if not query:
            messagebox.showerror("Error", "Please enter a query.")
            return

        self.log_query_to_excel(self.username, query)

        all_results = pd.DataFrame()
        series_choice = self.series_var.get()

        for server in self.server_listbox.get(0, tk.END):
            primary_ip = f"10.{series_choice}." + ".".join(server.split('.')[2:])
            messagebox.showinfo("Info", f"Attempting to connect to: {primary_ip}")
            result = self.connect_and_query(primary_ip, query)

            if result.empty:
                alternate_series = "28" if series_choice == "16" else "16"
                alternate_ip = f"10.{alternate_series}." + ".".join(server.split('.')[2:])
                messagebox.showinfo("Info", f"Attempting to connect to alternate IP: {alternate_ip}")
                result = self.connect_and_query(alternate_ip, query)

            if not result.empty:
                all_results = pd.concat([all_results, result], ignore_index=True)
            else:
                messagebox.showerror("Error", f"No results or connection error for {server}. Moving to next server...")

        if not all_results.empty:
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, all_results.to_string(index=False))
        else:
            messagebox.showinfo("Info", "No results from any server.")

    def download_results(self):
        results = self.results_text.get("1.0", tk.END)
        if not results.strip():
           messagebox.showwarning("Warning", "No results to download.")
           return

    # Convert results to DataFrame
        df = pd.read_csv(BytesIO(results.encode()), sep=r'\s+')

    # Define default download path
        download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        file_path = os.path.join(download_folder, "query_results.xlsx")

    # Save the file without asking for the location
        try:
           df.to_excel(file_path, index=False)
           messagebox.showinfo("Success", f"Results downloaded successfully to {file_path}!")
        except Exception as e:
           messagebox.showerror("Error", f"Failed to download results: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLQueryApp(root)
    root.mainloop()
