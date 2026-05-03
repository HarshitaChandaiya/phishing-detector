import re
import streamlit as st
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_TLDS = ['xyz','ru','tk','ml','ga','cf','gq','pw','top','click','download','loan','win']
BRAND_KEYWORDS  = ['paypal','amazon','apple','google','microsoft','facebook','instagram','netflix','bank']
LEGIT_DOMAINS   = ['paypal.com','amazon.com','apple.com','google.com','microsoft.com','facebook.com']

def check_https(url):
    p = url.startswith('https://')
    return {'name':'HTTPS check','passed':p,'detail':'Encrypted connection' if p else 'No HTTPS — red flag','score':0 if p else 15}

def check_ip(hostname):
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
    return {'name':'IP address check','passed':not is_ip,'detail':'Uses domain name' if not is_ip else f'{hostname} is a raw IP','score':25 if is_ip else 0}

def check_length(url):
    p = len(url) <= 75
    return {'name':'URL length','passed':p,'detail':f'{len(url)} characters — {"OK" if p else "suspiciously long"}','score':0 if p else 10}

def check_tld(tld):
    s = tld.lower() in SUSPICIOUS_TLDS
    return {'name':'TLD check','passed':not s,'detail':f'.{tld} is suspicious' if s else f'.{tld} looks fine','score':20 if s else 0}

def check_brand(url, domain, suffix):
    full = f"{domain}.{suffix}"
    hit  = next((b for b in BRAND_KEYWORDS if b in url.lower()), None)
    legit = full in LEGIT_DOMAINS
    sp = hit and not legit
    return {'name':'Brand impersonation','passed':not sp,'detail':f'"{hit}" found but not official' if sp else 'No spoofing detected','score':25 if sp else 0}

def check_hyphens(hostname):
    c = hostname.count('-')
    p = c < 3
    return {'name':'Hyphen count','passed':p,'detail':f'{c} hyphens — suspicious' if not p else f'{c} hyphens — normal','score':10 if not p else 0}

def check_at(url):
    h = '@' in url
    return {'name':'@ symbol','passed':not h,'detail':'@ found — redirect trick!' if h else 'No @ symbol','score':20 if h else 0}

def analyze(url):
    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    ext    = tldextract.extract(url)
    host   = parsed.hostname or ''
    checks = [check_https(url), check_ip(host), check_length(url),
              check_tld(ext.suffix), check_brand(url, ext.domain, ext.suffix),
              check_hyphens(host), check_at(url)]
    score   = min(sum(c['score'] for c in checks), 100)
    verdict = 'SAFE' if score < 20 else 'SUSPICIOUS' if score < 50 else 'PHISHING'
    return {'url': url, 'score': score, 'verdict': verdict, 'checks': checks}

# --- UI ---
st.set_page_config(page_title='Phishing URL Detector', page_icon='🛡️', layout='centered')
st.title('🛡️ Phishing URL Detector')
st.caption('Enter any URL to check if it is safe or a phishing attempt.')

url = st.text_input('', placeholder='https://example.com/login')

st.markdown('**Try these:**')
cols = st.columns(4)
if cols[0].button('Suspicious'):
    url = 'http://paypa1-secure.xyz/login'
if cols[1].button('Safe'):
    url = 'https://google.com'
if cols[2].button('IP-based'):
    url = 'http://192.168.1.1/bank/login.php'
if cols[3].button('Spoofed'):
    url = 'https://amazon.com.account-update.ru/signin'

if url:
    result = analyze(url)
    score  = result['score']

    if score < 20:
        verdict_color = 'green'
        emoji = '✅'
        msg = 'No significant phishing indicators found.'
    elif score < 50:
        verdict_color = 'orange'
        emoji = '⚠️'
        msg = 'Some red flags detected. Proceed with caution.'
    else:
        verdict_color = 'red'
        emoji = '🚨'
        msg = 'High risk! Do not enter any credentials.'

    st.divider()
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric(label='Risk Score', value=f'{score}/100')
    with col2:
        st.markdown(f'### {emoji} :{verdict_color}[{result["verdict"]}]')
        st.caption(msg)

    st.progress(score / 100)
    st.divider()

    st.markdown('**Check results:**')
    for c in result['checks']:
        icon = '✅' if c['passed'] else '❌'
        status = 'green' if c['passed'] else 'red'
        st.markdown(f'{icon} :{status}[**{c["name"]}**] — {c["detail"]}')