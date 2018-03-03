
'Create Installer object.
 Dim Installer
 Set Installer = CreateObject("WindowsInstaller.Installer")
 'Open the MSI database. You may change the path information as you like.
 Dim Database
 Set Database = Installer.OpenDatabase(WScript.Arguments(0), 0)
 'Create the SQL statement for query
 Dim SQL
 SQL = "SELECT * FROM Property WHERE Property = 'ProductVersion'"
 'Open the view and execute the SQL statement
 Dim View
 Set View = DataBase.OpenView(SQL)
 View.Execute
 'Fetch the record for the "ProductVersion" property
 Dim Record
 Set Record = View.Fetch
 'Show the result.
 WScript.echo Record.StringData(2)
