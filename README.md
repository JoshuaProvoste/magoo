<a name="readme-top"></a>

<br />
<div align="center">
    <img src="images/mr_magoo.jpg" alt="Mr. Magoo" width="118" height="236">

  <h1 align="center">Magoo</h1>
  <h2 align="center">Header fuzzing based on a HackerOne report about Blind SSRF (Server-Side Request Forgery)</h2>
</div>

## Contact

* Feel free to ping-me on Twitter [@JoshuaProvoste](https://twitter.com/JoshuaProvoste)
* Remember, Magoo is just a debugging script, I cannot give a guarantee of a completely correct operation

## About Magoo

<img src="images/slack_flowchart_example.png" alt="Slack Flowchart" width="670" height="194">

Nowadays, in just a single HTTP request, cloud infrastructure involve too many components like WAF, Proxy, Firewall, API management (a long etcetera); and they handle HTTP headers with custom settings.

In this way, I paid attention to this HackerOne report <a href="https://hackerone.com/reports/727330">https://hackerone.com/reports/727330</a>, **it was scored with medium severity and awarded with $500 USD for bug bounty.**

The researcher explain how to scan ports of IP adresses in a private network, using an specific type of HTTP header (*forwarded*), exploiting a Blind SSRF (Server-Side Request Forgery) vulnerability with time-delay technique.

The key points:
* The SSRF vulnerability could be present in authenticated and unauthenticated flows
* Originally was used a PNG file, but it could be any file or endpoint

### Magoo features

* Magoo is a debugging script for fuzzing and detection, not-a-one-click-tool
* Magoo use an extended list of *forwarded* type HTTP headers
* Detection of 429 rate limit status code
* Automated log file reports for stderr and stdout (TXT format)
* Real-time notifications using a basic Telegram bot
* Friendly with Linux based VPS (Debian and Ubuntu)

## Getting Started

### Installation

1. Clone the repository and move inside
  ```
  git clone https://github.com/JoshuaProvoste/SSRF-Magoo.git 
  cd SSRF-Magoo
  ```
2. Creating and activating a Python environment
  ```
  python3 -m venv environment
  source environment/bin/activate
  ```

### Requirements

3. Install modules from requirements.txt
  ```
  python3 -m pip install -r requirements.txt
  ```
4. Setting up your Telegram token and ID (Magoo work's with a little function that send notifications to a Telegram bot)
  ```
  export bot_token=token
  export bot_id=id
  ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

* The script options:
  ```
  python3 magoo.py -h
  ```
* Example of correct scanning:
  ```
  python3 magoo.py -H headers.txt -T target_list.txt
  ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### `-H` tag

According to the key points, this SSRF vulnerability could be present in authenticated and unauthenticated flows. And as a consequence is absolutely needed the usage of HTTP headers for a user session (Cookie, Authorization Bearer, API key, etc.). An example of content for `headers.txt`:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 
Cookie: cookie_type=sesion_value;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
(...)
```

### `-T` tag

This option use `target_list.txt` for which I recommend the following step-by-tep using the tools of https://github.com/projectdiscovery:


1. Performing a subdomain enumeration with `subfinder`:
  ```
  subfinder -d example.com -all -o subfinder.txt
  ```
2. Filter by online assets with `httpx`:
  ```
  httpx -l subfinder.txt -o httpx.txt
  ```
3. Crawl with `katana`:
  ```
  katana -list httpx.txt -d 10 -jc -kf all -o katana.txt
  ```
4. Generate `target_list.txt` filtering by status code with `httpx`:
  ```
  httpx -l katana.txt -mc 200,201,202,206,207,208,226 -o target_list.txt
  ```

An example of content for `target_list.txt`:
```
https://sub.example.com/path/storage/files/document.pdf
https://mirror.sub.example.com/login
https://www.example.com/assets/js/library.js
(...)
```

This 4 step-by-step to generate a `target_list.txt` is for unauthenticated flows. If you want to crawl as authenticated user, review the options of each tool in order to append your HTTP header for authentication and authorization.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Verification

If you're lucky (😂) using Magoo, please use the following resources:

* https://www.youtube.com/watch?v=j5_WicLwwC4
* https://www.hackerone.com/application-security/how-server-side-request-forgery-ssrf
<img src="images/port_scanning_time_delays.png" alt="Slack Flowchart" width="741" height="563">

```
date1=`date +%s`; while true; do echo -ne "$(date -u --date @$((`date +%s` - $date1)) +%H:%M:%S)\r"; done
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>