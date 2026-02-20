#!/usr/bin/python3
#_*_ coding: utf8 _*_

#Coded by https://twitter.com/JoshuaProvoste
#Based on https://hackerone.com/reports/727330

import time
import os
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from urllib.parse import urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('-H','--headers', type=str, required=True, help='Readable file with custom HTTP headers for browser and session emulation')
parser.add_argument('-T','--target', type=str, required=True, help='Readable file with multiple URLs previously validated')
args = parser.parse_args()

def escape_markdown_v2(text: str) -> str:
    """
    Escapa caracteres especiales para Telegram parse_mode=MarkdownV2.
    Referencia rápida: Telegram MarkdownV2 requiere escapar varios símbolos.
    """
    if text is None:
        return ""
    # Importante: primero escapar backslash
    text = text.replace("\\", "\\\\")
    # Caracteres a escapar en MarkdownV2
    for ch in ["_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"]:
        text = text.replace(ch, f"\\{ch}")
    return text


def bot_telegram(bot_message, bot_token, bot_id):
    """
    Envía mensaje a Telegram de forma más segura/estable:
    - POST (no GET)
    - Sin querystring manual
    - timeout
    - Escape para MarkdownV2
    """
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": bot_id,
            "text": escape_markdown_v2(bot_message),
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True,
        }
        # timeout corto para que no congele el scan si Telegram está lento
        return requests.post(url, json=payload, timeout=5)
    except Exception:
        # No tumbar el scan si Telegram falla
        return None
def stderr_log(target,e):
    log = open('stderr_log_ssrf.txt', 'a')
    log.write('[-] Unexpected error with this URL: '+target+' Error: '+e+'\n')
    log.close()
    return print('[-] Unexpected error with this URL: '+target+' Error: '+e)
def stdout_log(status_code, ssrf, target, elapsed=None):
    log = open('stdout_log_ssrf.txt', 'a')
    if elapsed is not None:
        log.write('[+] Status: '+status_code+' Elapsed: '+f'{elapsed:.3f}'+'s Header: '+ssrf+' URL: '+target+'\n')
        log.close()
        return print('[+] Status: '+status_code+' Elapsed: '+f'{elapsed:.3f}'+'s Header: '+ssrf+' URL: '+target)
    else:
        log.write('[+] Status: '+status_code+' Header: '+ssrf+' URL: '+target+'\n')
        log.close()
        return print('[+] Status: '+status_code+' Header: '+ssrf+' URL: '+target)
def load_headers_from_file(headers_path: str) -> dict:
    """
    Lee un archivo .txt con headers en formato:
      Header-Name: value
    - Soporta valores con ':' (usa partition / split 1 vez)
    - NO elimina espacios internos del valor (solo strip)
    - Ignora líneas vacías o sin ':'
    """
    headers = {}
    with open(headers_path, 'r', encoding='utf-8', errors='replace') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or ":" not in line:
                continue

            name, sep, value = line.partition(":")
            if sep != ":":
                continue

            name = name.strip()
            value = value.strip()

            if not name:
                continue

            headers[name] = value

    return headers

def run_scan(bot_token, bot_id, target_list, forwarded_headers, base_headers):
    """
    Ejecuta el escaneo sin mutar el dict global de headers.
    En cada request crea un dict nuevo: headers = base_headers.copy()
    Mide elapsed real por request con time.monotonic().
    Reusa conexiones con requests.Session().
    """
    session = requests.Session()

    for target in target_list:
        for ssrf in forwarded_headers:
            try:
                headers = base_headers.copy()

                parsed = urlsplit(target)
                host_value = parsed.netloc
                if not host_value:
                    host_value = target.split('/')[2]

                headers['Host'] = host_value
                headers['Referer'] = target
                headers[ssrf] = 'fake.tld'

                start = time.monotonic()
                r = session.get(
                    url=target,
                    headers=headers,
                    verify=False,
                    allow_redirects=False,
                    timeout=5
                )
                elapsed = time.monotonic() - start

                status_code = str(r.status_code)

                if status_code == '429':
                    print('[-] Rate limit exception. Good bye!')
                    bot_telegram('[-] Scan aborted by 429 Rate limit.', bot_token, bot_id)
                    exit()
                elif status_code[0] == '2':
                    pass
                elif status_code[0] == '3':
                    pass
                elif status_code[0] == '4':
                    pass
                else:
                    stdout_log(status_code, ssrf, target, elapsed=elapsed)
                    bot_telegram(
                        '[+] Status: '+status_code+' Elapsed: '+f'{elapsed:.3f}'+'s Header: '+ssrf+' URL: '+target,
                        bot_token, bot_id
                    )

            except KeyboardInterrupt:
                print('Good bye!')
                exit()
            except requests.exceptions.Timeout as e:
                e = str(e)
                stderr_log(target, e)
                bot_telegram('[-] Unexpected error: ' + e, bot_token, bot_id)
                pass
            except requests.exceptions.InvalidURL as e:
                e = str(e)
                stderr_log(target, e)
                bot_telegram('[-] Unexpected error: ' + e, bot_token, bot_id)
                pass
            except Exception as e:
                e = str(e)
                stderr_log(target, e)
                bot_telegram('[-] Unexpected error: ' + e, bot_token, bot_id)
                pass

bot_token = os.environ.get('bot_token')
bot_id = os.environ.get('bot_id')

file_headers_dict = load_headers_from_file(args.headers)

forwarded_headers = ['Forwarded','X-Forwarded','X-Forwarded-Host','X-Forwarded-By','X-Forwarded-For','X-Forwarded-Server','X-Real-IP','X-Forwarded-Proto','X-Forwarded-For-Original','X-Forward-For','Forwarded-For-IP','X-Originating-IP','X-Forwarded-For-IP','X-Forwarded-Port','X-Remote-IP','X-Remote-Addr','X-Remote-Host','X-Server-Name','X-Client-IP','Client-Ip','X-Host','Origin','Access-Control-Allow-Origin','X-ProxyUser-Ip','X-Cluster-Client-Ip','CF-Connecting-IP','True-Client-IP','X-Backend-Host','X-BlueCoat-Via','X-Forwared-Host','X-From-IP','X-Gateway-Host','X-Ip','X-Original-Host','X-Original-IP','X-Original-Remote-Addr','X-Original-Url','X-Originally-Forwarded-For','X-ProxyMesh-IP','X-True-Client-IP','Proxy-Host','CF-ipcountry','Remote-addr','Remote-host','X-Backend-Server','HTTP-Host','Local-addr','X-CF-URL','Fastly-Client-IP','Home','Host-Name','Host-Liveserver','X-Client-Host','X-Clientip','X-Forwarder-For','X-Machine','X-Network-Info','X-Orig-Client','Xproxy','X-Proxy-Url','Clientip','Hosti','Incap-Client-Ip','X-User','X-Source-IP']

target_list = open(args.target,'r').readlines()
target_list = [x.strip() for x in target_list]

if (bot_token != None and bot_id != None):
    run_scan(bot_token, bot_id, target_list, forwarded_headers, file_headers_dict)
    print('[+] Scan finished. Good bye!')
    bot_telegram('[+] Scan finished. Good bye!', bot_token, bot_id)
    exit()
else:
    print('[-] This app requires 2 variable environments (token and id) for Telegram notifications. Example: export bot_token=token / export bot_id=id')
    exit()