# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

"""Tool for web browse."""

import ipaddress
import socket
import urllib.parse
import requests


def _is_safe_ip(ip_str: str) -> bool:
  try:
    ip = ipaddress.ip_address(ip_str)
  except ValueError:
    return False

  if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
    return False

  # Explicitly check for known metadata service IP
  if str(ip) == "169.254.169.254":
    return False

  return True


def load_web_page(url: str) -> str:
  """Fetches the content in the url and returns the text in it.

  Args:
      url (str): The url to browse.

  Returns:
      str: The text content of the url.
  """
  from bs4 import BeautifulSoup

  try:
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
      return f"Invalid URL scheme: {parsed_url.scheme}"

    hostname = parsed_url.hostname
    if not hostname:
      return "Invalid URL: missing hostname"

    # Resolve IP addresses and check against safe list
    try:
      addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
      return f"Failed to resolve hostname: {hostname}"

    for result in addr_info:
      ip_addr = result[4][0]
      if not _is_safe_ip(ip_addr):
        return f"Access denied: URL resolves to a restricted IP address ({ip_addr})"

    # We use the original URL to preserve SNI and SSL certificate validation.
    # While this leaves a small TOCTOU window for DNS rebinding, it is
    # necessary to support HTTPS without complex custom transport adapters.

    # Set allow_redirects=False to prevent SSRF attacks via redirection.
    response = requests.get(url, allow_redirects=False, timeout=10)

    if response.status_code == 200:
      soup = BeautifulSoup(response.content, 'lxml')
      text = soup.get_text(separator='\n', strip=True)
    else:
      text = f'Failed to fetch url: {url} (Status Code: {response.status_code})'

    # Split the text into lines, filtering out very short lines
    # (e.g., single words or short subtitles)
    return '\n'.join(line for line in text.splitlines() if len(line.split()) > 3)

  except Exception as e:
    return f'Error fetching url: {url} ({e})'
