"""URL patterns used to explain potentially suspicious parts of an address."""

ABUSED_TLDS: set[str] = {'bond', 'buzz', 'sbs', 'cc', 'zip', 'beer'}

SHORTENER_HOSTS: set[str] = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'tiny.cc', 'short.cm', 'adf.ly', 'clk.im', 'cutt.ly', 'rebrand.ly',
    'b.name', 'bit.do', 'rb.gy'
}

REDIRECT_KEYS: set[str] = {
    'redirect', 'next', 'url', 'target', 'return', 'returnurl', 'dest', 'destination',
    'continue', 'go', 'r', 'uri', 'redirecturl', 'redirect_uri'
}

SENSITIVE_WORDS: list[str] = [
    'login', 'logon', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'password', 'banking', 'webscr',
    'suspend', 'unlock', 'wallet', 'billing', 'authenticate', 'validate',
]
