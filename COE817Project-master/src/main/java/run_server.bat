@echo off
echo Starting Bank Server...
java -cp ".;sqlite-jdbc-3.42.0.0.jar" coe817.project.BankGateway
pause
