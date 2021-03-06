# sslite
A lightweight SSL/TLS configuration checking tool, written in Python v3 for the linux command line.

##### Example usage #####
user@vm1:~/Desktop$ python3 sslite.py

Or, after exporting the script to $PATH:

user@vm1:~/Desktop$ sslite

After approx. 30-60 seconds, a file will be saved to the same location that the script is executed from. If you were to run a scan against the hostname 'secure-now.io' on the 6th of October 2016 at 19:55, the file would be named 'secure-now.io-061016-1955.txt' (not an American date format!).

#

##### Info #####

Compatible with most Linux, Unix and FreeBSD operating systems (assuming that Python3 and OpenSSL are installed).

Executes successfully without root privileges (as long as you have file write permissions in the directory you are executing the scipt from).

The script requires modification to test non-standard ports (anything other than 443).

Maximum number of connections made = 137 + number of supported cipher suites (~145 in most cases). This is likely to be lower in reality, as your compilation of OpenSSL will not support all possible cipher suites.

#

##### Known Issues #####

If the site's cipher list is excessively large, the "percent complete" indicator will slow down significantly towards the end of runtime.

Entering an IP address instead of a hostname is not currently functional.

Returns ssl.CertificateError if you are located behind a captive portal with no internet access (rather than TimeoutError).

Cannot reliably identify SSLv2 (due to inherent lack of support in modern OpenSSL implementations).

No testing for the current drafts of TLSv1.3.

If a server is not configured to use its own preference of cipher, results are incorrect.

#

##### Upcoming Features #####

This section contains a list of desired and upcoming features for sslite.

These features will be marked with a '+' symbol. Once the feature has been added, it will be moved to the bottom and the '+' symbol will be replaced by a '#'.

+Portability to Python v2

+Identify when server is not set to prefer its own cipher list

+Identification of HTTP/2.0 and SPDY

+More in-depth validation of certificate (check trust store, CRL and OCSP)

+Ciphers negotiated by Top 10 popular browsers

+Level of support for older browsers

+Checks for certificate key length & signature algorithm

+Checks for key exchange parameter size

+Save a report file after scan completion (.html extension, inline styling)

+Non-invasive mode (rate-limiting connections)

+Accept command-line arguments


#Identify OpenSSL version being used

#Save a report file after scan completion (.txt extension)

#Ciphers available in order of server preference

#Estimated time to complete (percentage complete statements)

#Identify protocol version support

#Error handling

#Input validation of hostname

#Checks on HTTP Response headers

#Validation of certificate (currently checks that hostnames match & trust store if available)

#Unique names for reports

#
