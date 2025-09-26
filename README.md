# website-Scanner
Website scanning tool and detecting various bugs and vulnerabilities....


# install in termux
```
pkg install python
pkg install git
git clone https://github.com/silent-mimi/website-Scanner.git
cd website-Scanner
pip install -r requirements
```

# running in termux
```
python website-Scanner.py -h
```

# Full website scan
```
python website-Scanner.py -u https://www.example.com/
```

# sql test
```
python website-Scanner.py -u https://www.example.com/products?id=1 --sqli
```

# xss test and Generate HTML report
```
python website-Scanner.py -u https://www.example.com/search?q=test --xss -r scan_report.html
```

# Directory Traversal test
```
python website-Scanner.py -u https://www.example.com/download?file=document.pdf --dt
```

# IDOR test
```
python website-Scanner.py -u https://www.example.com/profile?user_id=123 --idor --idor-param user_id
```

# Specify a file to load SQLi payloads (instead of default payloads)
```
python website-Scanner.py -u https://www.example.com/item?id=1 --sqli --sqli-payloads custom_sqli_payloads.txt
```

# Create HTML report:
```
python website-Scanner.py -u http://example.com/target --report report.html
```

# Specifying URL for POST requests:
```
python website-Scanner.py --url http://example.com --data-url http://example.com/api/process --tests vuln --output report.html
```

```
python website-Scanner.py --url http://example.com --session-file cookies.json --scan-all --output report.html
```

# Using custom payloads:
```
python website-Scanner.py --url http://example.com --tests sql,xss --sql-payload-file custom_sql.txt --xss-payload-file custom_xss.txt --output report.html
```

# Login test with username and password list:
```
python website-Scanner.py --url http://example.com --username admin --tests creds --password-file my_passwords.txt --output report.html
```

# Running specific tests:
```
python website-Scanner.py --url http://example.com --tests basic,vuln --output report.html
```


# Run all tests:
```
python website-Scanner.py --url http://example.com --scan-all --output report.html
```


telegram = @silent_mimi
