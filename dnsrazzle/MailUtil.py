#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2025 SecurityShrimp LTD, LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


__version__ = '2.0.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

import configparser
import os
import smtplib
from datetime import datetime
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders

from .IOUtil import print_error, print_good, print_status


def load_config(config_path=None):
    """Load SMTP configuration from an INI file.

    Args:
        config_path: Path to the config file. Defaults to etc/mail_config.conf
                     relative to the working directory.

    Returns:
        dict with SMTP settings, or None if config is missing/invalid.
    """
    if config_path is None:
        config_path = os.path.join(os.getcwd(), 'etc', 'mail_config.conf')

    if not os.path.exists(config_path):
        print_error(f"Mail config not found: {config_path}")
        print_error("Copy etc/mail_config.conf.sample to etc/mail_config.conf and fill in your SMTP settings.")
        return None

    parser = configparser.ConfigParser()
    parser.read(config_path)

    try:
        config = {
            'host': parser.get('SMTP', 'host'),
            'port': parser.getint('SMTP', 'port', fallback=587),
            'tls': parser.getboolean('SMTP', 'tls', fallback=True),
            'username': parser.get('AUTH', 'username', fallback=''),
            'password': parser.get('AUTH', 'password', fallback=''),
            'from_email': parser.get('MAIL', 'from'),
            'recipients': [r.strip() for r in parser.get('MAIL', 'recipients').split(',') if r.strip()],
            'subject': parser.get('MAIL', 'subject', fallback='DNSRazzle Scan Report'),
        }
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print_error(f"Mail config error: {e}")
        return None

    if not config['host']:
        print_error("SMTP host is not configured in mail_config.conf")
        return None

    if not config['recipients']:
        print_error("No recipients configured in mail_config.conf")
        return None

    return config


def send_email(config, subject, html_body, attachments=None):
    """Send an email via SMTP.

    Args:
        config: dict from load_config().
        subject: Email subject line.
        html_body: HTML email body.
        attachments: optional list of (filename, data_bytes, mime_type) tuples.

    Returns:
        True on success, False on failure.
    """
    msg = MIMEMultipart("mixed")
    msg["From"] = config['from_email']
    msg["To"] = ", ".join(config['recipients'])
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    if attachments:
        for filename, data, mime_type in attachments:
            maintype, subtype = mime_type.split("/", 1) if "/" in mime_type else ("application", "octet-stream")
            part = MIMEBase(maintype, subtype)
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(part)

    try:
        if config['tls']:
            server = smtplib.SMTP(config['host'], config['port'], timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(config['host'], config['port'], timeout=10)

        if config['username'] and config['password']:
            server.login(config['username'], config['password'])

        server.sendmail(config['from_email'], config['recipients'], msg.as_string())
        server.quit()
        return True

    except Exception as e:
        print_error(f"Failed to send email: {e}")
        return False


def send_report(out_dir, domains_scanned, config_path=None):
    """Send a scan completion report email with CSV attachments.

    Args:
        out_dir: Output directory containing the CSV files.
        domains_scanned: list of domain names that were scanned.
        config_path: Optional path to mail_config.conf.
    """
    config = load_config(config_path)
    if config is None:
        return

    domain_list = ', '.join(domains_scanned)
    date_str = datetime.now().strftime('%m/%d/%Y %H:%M')
    subject = f"{config['subject']} — {date_str}"

    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 24px;">
        <h2 style="color: #22c55e; margin: 0 0 16px;">DNSRazzle Scan Completed</h2>
        <p style="color: #e0e0e0; font-size: 15px; line-height: 1.6; margin: 0 0 8px;">
            Scan completed for: <strong style="color: #fff;">{domain_list}</strong>
        </p>
        <p style="color: #e0e0e0; font-size: 15px; line-height: 1.6; margin: 0 0 8px;">
            Results are attached as CSV files.
        </p>
        <p style="color: #888; font-size: 13px; margin: 16px 0 0;">
            Generated by DNSRazzle v{__version__} on {date_str}
        </p>
    </div>
    """

    attachments = []
    for csv_name in ['discovered-domains.csv', 'domain_similarity.csv']:
        csv_path = os.path.join(out_dir, csv_name)
        if os.path.exists(csv_path):
            with open(csv_path, 'rb') as f:
                attachments.append((csv_name, f.read(), 'text/csv'))

    if not attachments:
        print_error("No CSV files found to attach to email report")
        return

    print_status("Sending email report...")
    if send_email(config, subject, html_body, attachments):
        print_good(f"Email report sent to {', '.join(config['recipients'])}")
    else:
        print_error("Failed to send email report")
