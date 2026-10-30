def csv_safe(v):
    """Neutralise spreadsheet formula injection in exported CSV cells."""
    s = "" if v is None else str(v)
    return "'" + s if s and s[0] in "=+-@\t\r" else s
