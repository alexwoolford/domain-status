# domain_status

[![Rust](https://github.com/alexwoolford/domain_status/actions/workflows/rust.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/rust.yml)

**domain_status** is a Rust-based tool designed for multithreaded checking of URL statuses and redirections. It captures errors, tracks progress, and records results in a SQLite database.

## 🌟 Features

* **Speedy Execution**: Utilizes multithreading to process URLs rapidly.
* **Accurate Monitoring**: Keeps track of various connection and DNS issues.
* **Comprehensive Reports**: Provides regular status updates and a detailed error summary after execution.
* **Data Storage**: Saves results to a SQLite database for easy access and further analysis.
* **Domain Insights**: Extracts domains from URLs and captures critical data like final domain after redirection.

## 🔧 Getting Started

### Building
To get started, first build the project:

    cargo build --release

This creates an executable in the ./target/release/ directory.

### Usage
Run the tool with a list of URLs:

    domain_status urls.txt

### Data Captured

| Field                   | Description                                                    |
|-------------------------|----------------------------------------------------------------|
| domain                  | Initial domain of the URL                                      |
| final_domain            | Final domain after redirections                                |
| ip_address              | IP address of the domain                                       |
| reverse_dns_name        | Reverse DNS name of the IP address                             |
| status                  | HTTP status code                                               |
| status_description      | Description of the HTTP status code                            |
| response_time           | Time taken to get the response (in seconds)                    |
| title                   | Title of the web page                                          |
| keywords                | Meta keywords from the web page                                |
| description             | Meta description from the web page                             |
| linkedin_slug           | LinkedIn slug from the company's LinkedIn URL                  |
| security_headers        | Security headers present in the HTTP response                  |
| tls_version             | TLS version used by the server                                 |
| ssl_cert_subject        | Subject of the SSL certificate                                 |
| ssl_cert_issuer         | Issuer of the SSL certificate                                  |
| ssl_cert_valid_from     | Validity start date of the SSL certificate                     |
| ssl_cert_valid_to       | Validity end date of the SSL certificate                       |
| oids                    | OIDs from the SSL certificate                                  |
| is_mobile_friendly      | Indicates if the page is mobile-friendly (presence of viewport)|
| timestamp               | Timestamp when the data was captured                           |

## 📊 Output
Stay informed with detailed logging:

```plaintext
✔️ domain_status::database [INFO] Database file created successfully.
✔️ domain_status [INFO] Processed 1506 lines in 5.33 seconds (~282.29 lines/sec)
✔️ domain_status [INFO] Processed 1851 lines in 10.32 seconds (~179.39 lines/sec)
✔️ domain_status [INFO] Processed 1856 lines in 15.23 seconds (~121.87 lines/sec)
✔️ domain_status [INFO] Error Counts:
✔️ domain_status [INFO]    HTTP request redirect error: 2
✔️ domain_status [INFO]    HTTP request timeout error: 154
✔️ domain_status [INFO]    HTTP request error: 544
✔️ domain_status [INFO]    Title extract error: 49
✔️ domain_status [INFO]    Process URL timeout: 144
```

## 🚀 Performance & Scalability
Designed with scalability in mind, domain_status ensures smooth operation even with large files. If you encounter system-specific errors related to file limits, check and adjust your system's ulimit settings.
