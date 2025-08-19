import dnsscope
from flask import Flask,request,redirect,send_file
from multiprocessing import Process
from openpyxl import Workbook
import io
import re
import math
import sqlite3
import os
import json

app = Flask(__name__)

DB_FILE = "DNSscope.db"

def get_navbar():
    return """
    <div style="background-color:#333; padding:10px; text-align:center;">
        <a href="/explicit-inscope" style="color:white; margin:0 15px; text-decoration:none;">Explicitly In-Scope</a>
        <a href="/implicit-inscope" style="color:white; margin:0 15px; text-decoration:none;">Implicitly In-Scope</a>
        <a href="/flds" style="color:white; margin:0 15px; text-decoration:none;">Free-level Domains</a>
        <a href="/process-new-flds" style="color:white; margin:0 15px; text-decoration:none;">New FLDs</a>
        <a href="/export" style="color:white; margin:0 15px; text-decoration:none;">Export</a>
        <a href="/processed" style="color:white; margin:0 15px; text-decoration:none;">Processed</a>
        <a href="/dead-domains" style="color:white; margin:0 15px; text-decoration:none;">Dead Domains</a>
    </div>
    """

@app.route("/")
def root():
    return redirect('/explicit-inscope')

@app.route("/explicit-inscope", methods=["GET"])
def explicit_inscope():
    return render_data("Explicit")

@app.route("/implicit-inscope", methods=["GET"])
def implicit_inscope():
    return render_data("Implicit")
    
def render_data(is_explicit):
    if is_explicit == "Explicit":
        inscope = True
    else:
        inscope = False

    search_flag = request.args.get("search", "").lower() == "true"
    ip_filter_raw = request.args.get("ip", "")
    ip_filter = re.sub(r"[^0-9.]", "", ip_filter_raw)
    domain_filter_raw = request.args.get("domain", "")
    # Only allow alphanumeric searches, dots, and dashes
    domain_filter = re.sub(r"[^A-Za-z0-9-.]", "", domain_filter_raw)
    
    limit = int(request.args.get("limit", 50))
    page = int(request.args.get("page", 1))
    offset = (page - 1) * limit

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
        
    # First, get total rows for the current filter
    if search_flag:
        if ip_filter and domain_filter:
            c.execute("SELECT COUNT(*) FROM data WHERE ip LIKE ? AND domains LIKE ? AND ip_inscope = ?", (f"%{ip_filter}%", f"%{domain_filter}%", inscope))
        elif ip_filter:
            c.execute("SELECT COUNT(*) FROM data WHERE ip LIKE ? and ip_inscope = ?", (f"%{ip_filter}%",inscope))
        elif domain_filter:
            c.execute("SELECT COUNT(*) FROM data WHERE domains LIKE ? and ip_inscope = ?", (f"%{domain_filter}%",inscope))
        else:
            c.execute("SELECT COUNT(*) FROM data WHERE ip_inscope = ?", (inscope,))
    else:
        c.execute("SELECT COUNT(*) FROM data WHERE ip_inscope = ?", (inscope,))
    total_rows = c.fetchone()[0]
    total_pages = math.ceil(total_rows / limit)

    if search_flag:
        if ip_filter and domain_filter:
            c.execute("SELECT ip, domains FROM data WHERE ip LIKE ? AND domains LIKE ? AND ip_inscope = ? LIMIT ? OFFSET ?", (f"%{ip_filter}%", f"%{domain_filter}%", inscope, limit, offset))
        elif ip_filter:
            c.execute("SELECT ip, domains FROM data WHERE ip LIKE ? AND ip_inscope = ? LIMIT ? OFFSET ?", (f"%{ip_filter}%", inscope, limit, offset))
        elif domain_filter:
            c.execute("SELECT ip, domains FROM data WHERE domains LIKE ? AND ip_inscope = ? LIMIT ? OFFSET ?", (f"%{domain_filter}%", inscope, limit, offset))
        else:
            c.execute("SELECT ip, domains FROM data WHERE ip_inscope = ? LIMIT ? OFFSET ?", (inscope, limit,offset))
    else:
        c.execute("SELECT ip, domains FROM data WHERE ip_inscope = ? LIMIT ? OFFSET ?", (inscope, limit,offset))


    rows = c.fetchall()
    conn.close()

    html = f"""
    <html>
    <head>
        <title>{is_explicit} In-Scope</title>
        <style>
            table {{ border-collapse: collapse; width: 80%; margin: 20px auto; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            body {{ font-family: Arial, sans-serif; }}
            h1 {{ text-align: center; }}
            h2 {{ text-align: center; }}
            p {{ text-align: center; }}
            form {{ text-align: center; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        {get_navbar()}
        <h2>Data for IP Addresses that are {is_explicit.lower()}ly in-scope<br></h2>
        <p>{"(FLD is in scope but IP address is not explicitly in-scope)" if not inscope else ""}</p>
        <form method="GET">
            <input type="hidden" name="search" value="true">
            <input type="text" name="ip" value="{ip_filter}" placeholder="Search IP">
            <input type="text" name="domain" value="{domain_filter}" placeholder="Search Domain">
            <label for="limit">Rows per page:</label>
            <select name="limit">
                <option value="10" {"selected" if limit == 10 else ""}>10</option>
                <option value="25" {"selected" if limit == 25 else ""}>25</option>
                <option value="50" {"selected" if limit == 50 else ""}>50</option>
                <option value="100" {"selected" if limit == 100 else ""}>100</option>
            </select>
            <input type="submit" value="Apply">
        </form>
        <table>
            <tr>
                <th>#</th>
                <th>IP</th>
                <th>Domain</th>
            </tr>
        <p><br><u>Total Rows:
        {total_rows}</u>
        </p>"""
    
    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&ip={ip_filter}&domain={domain_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"
    
    i = 1
    for row in rows:
        html += f"<tr><td>{i}</td><td>{row[0]}</td><td>{row[1]}</td></tr>"
        i=i+1
    html += "\n</table>\n"

    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&ip={ip_filter}&domain={domain_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"

    return html

@app.route("/process-new-flds", methods=["POST","GET"])
def process_new_flds():
    checked_values_raw = request.form.getlist("fld_values[]")  # list of checked values
    # sanitize user input:
    checked_values = [re.sub(r"[^A-Za-z0-9-.]", "", fld) for fld in checked_values_raw]
    confirmed = request.form.get("confirmed","").lower() == "true"
    html = f"""
    <html>
    <head>
        <title>Process New FLDs</title>
        <style>
            body {{ text-align: center; font-family: Arial, sans-serif; }}
            h1 {{ text-align: center; }}
            h2 {{ text-align: center; }}
            form {{ text-align: center; margin-bottom: 20px; }}
            label {{ text-align: center; }}
        </style>
    </head>
    <body>
        {get_navbar()}
        <h2>Process new FLDs</h2>
    """
    if confirmed:
        html += "Submitted the following values for processing:"
        html += f"<br><br><b>{', '.join(checked_values)}</b><br>"
        p = Process(target=run_in_background, args=(checked_values,))
        p.start()
        return html
    if checked_values:
        html += "Would you like to mark the following FLDs as in-scope? <br>This will mark them as in-scope and submit them for further analysis:"
        html += f"<br><br><b>{', '.join(checked_values)}</b><br>"
        html += f'<form class="fld" action="/process-new-flds" method="post">'
        for fld in checked_values:
            html += f'<input type="hidden" name="fld_values[]" value="{fld}">'
        html += '<br><button type="submit" name="confirmed" value="true">Confirm all above FLDs as in-scope</button></body>'
    else:
        html += "Submit values from the Free-Level Domains page for additional processing"
        html += "<br><br><a href='/flds'>Free-Level Domains</a>"
    return html

def run_in_background(flds):
    dnsscope.processNewFlds(flds)

@app.route("/flds", methods = ["GET"])
def free_level_domains():
    search_flag = request.args.get("search", "").lower() == "true"
    inscope_raw = request.args.get("fld_inscope", "")
    inscope = re.sub(r"[^0-2]", "", inscope_raw)
    fld_filter_raw = request.args.get("fld_keyword", "")
    fld_filter = re.sub(r"[^A-Za-z0-9-.]", "", fld_filter_raw)
    whois_filter_raw = request.args.get("whois_keyword", "")
    whois_filter = re.sub(r"[^A-Za-z0-9-.]", "", whois_filter_raw)
    
    limit_raw = request.args.get("limit", "ALL")
    if limit_raw != "ALL":
        limit = int(limit_raw)
        page = int(request.args.get("page", 1))
        offset = (page - 1) * limit
    elif limit_raw == "ALL":
        limit = limit_raw


    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    inscope_filter = "%"
    if inscope == "0":
        inscope_filter = "pending"
    elif inscope == "1":
        inscope_filter = "true"

    # First, get total rows for the current filter
    c.execute("SELECT COUNT(*) FROM flds WHERE fld_inscope LIKE ? AND fld LIKE ? AND whoisdata LIKE ?", (inscope_filter,f"%{fld_filter}%", f"%{whois_filter}%"))
    total_rows = c.fetchone()[0]

    if limit == "ALL":
        total_pages = 1
        limit = total_rows
        offset = 0
        page = 1
    else:
        total_pages = math.ceil(total_rows / limit)

    c.execute("SELECT * FROM flds WHERE fld_inscope LIKE ? AND fld LIKE ? AND whoisdata LIKE ? LIMIT ? OFFSET ?", (inscope_filter,f"%{fld_filter}%", f"%{whois_filter}%", limit, offset))

    rows = c.fetchall()
    conn.close()

    html = f"""
    <html>
    <head>
        <title>Free-Level Domains (FLDs)</title>
        <style>
            table {{ border-collapse: collapse; width: 100%; margin: 20px auto; table-layout: fixed;}}
            th, td {{ border: 1px solid #ccc; padding: 4px; text-align: left; }}
            td.number-col,th.number-col {{ width: 10px; text-align: center; }}
            td.fld-col,th.fld-col {{ width: 150px; text-align: left; }}
            td.scope-col,th.scope-col {{ width: 50px; text-align: left; }}
            td.whois-col,th.whois-col {{ width: 900px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            body {{ font-family: Arial, sans-serif; }}
            h1 {{ text-align: center; }}
            h2 {{ text-align: center; }}
            form {{ text-align: center; margin-bottom: 20px; }}
            form.fld {{ text-align: left; }}
            label {{ text-align: left; }}
            p {{ text-align: center; }}
        </style>
    </head>
    <body>
        {get_navbar()}
        <h2>All Free-Level Domains (FLDs) discovered during processing</h2>
        <form method="GET">
            <input type="hidden" name="search" value="true">
            <input type="text" name="fld_keyword" value="{fld_filter}" placeholder="Search FLDs">
            <input type="text" name="whois_keyword" value="{whois_filter}" placeholder="Search whoisdata">
            <label for="limit">Rows per page:</label>
            <select name="limit">
                <option value="10" {"selected" if limit == 10 else ""}>10</option>
                <option value="25" {"selected" if limit == 25 else ""}>25</option>
                <option value="50" {"selected" if limit == 50 else ""}>50</option>
                <option value="100" {"selected" if limit == 100 else ""}>100</option>
                <option value="ALL" {"selected" if limit_raw == "ALL" else ""}>ALL</option>
            </select>
            <br><br><b>Filter on whether FLD is in-scope</b><br><br>
            <label><input type="radio" name="fld_inscope" value="3" {"checked" if inscope_filter == "%" else ""}>All</label>
            <label><input type="radio" name="fld_inscope" value="0" {"checked" if inscope_filter == "pending" else ""}>FLD out-of-scope</label>
            <label><input type="radio" name="fld_inscope" value="1" {"checked" if inscope_filter == "true" else ""}>FLD in-scope</label>
            <br><br><input type="submit" value="Apply Search Filter">
        </form>
        <br><br><br><u><p>Total Rows:
        {total_rows}</u></p>
        """
    
    # Pagination links top
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&inscope={inscope}&fld_keyword={fld_filter}&whois_keyword={whois_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"
    
    # Table headers, select all, and submit for processing
    html += """
    <p>
    <input type="checkbox" id="select-all">    Select All?</p>
    <form class="fld" action="/process-new-flds" method="post">
    <button type="submit">Submit all checked FLDs as in-scope</button>
        <table>
            <tr>
                <th class='number-col'>#</th>
                <th class='fld-col'>Free-Level Domain<br></th>
                <th class='scope-col'>FLD In Scope?</th>
                <th class='whois-col'>Whois Data</th>
            </tr>
    """
    
    # Table data
    i = 1
    for row in rows:
        html += f"<tr><td class='number-col'>{i}</td><td class='fld-col'><input type='checkbox' class='fld' name='fld_values[]' value='{row[0]}'>{row[0]}</td><td class='scope-col'>{row[1]}</td><td class='whois-col'>{row[2]}</td></tr>"
        i=i+1
    html += "\n</table></form>\n"

    # Pagination links bottom
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&inscope={inscope}&fld_keyword={fld_filter}&whois_keyword={whois_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"
    html += """<script>
    document.getElementById('select-all').addEventListener('change', function() {
        document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            if (cb !== this) cb.checked = this.checked;
        });
    });
    </script>"""

    return html

@app.route("/dead-domains", methods=["GET"])
def dead_domains():
    search_flag = request.args.get("search", "").lower() == "true"
    domain_filter_raw = request.args.get("domain", "")
    # Only allow alphanumeric searches, dots, and dashes
    domain_filter = re.sub(r"[^A-Za-z0-9-.]", "", domain_filter_raw)
    
    limit = int(request.args.get("limit", 50))
    page = int(request.args.get("page", 1))
    offset = (page - 1) * limit

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
        
    # First, get total rows for the current filter
    if search_flag:
        if domain_filter:
            c.execute("SELECT COUNT(*) FROM data WHERE domains LIKE ?", (f"%{domain_filter}%",))
        else:
            c.execute("SELECT COUNT(*) FROM data")
    else:
        c.execute("SELECT COUNT(*) FROM data")
    total_rows = c.fetchone()[0]
    total_pages = math.ceil(total_rows / limit)

    if search_flag:
        if domain_filter:
            c.execute("SELECT domain FROM dead_domains WHERE domain LIKE ? LIMIT ? OFFSET ?", (f"%{domain_filter}%", limit, offset))
        else:
            c.execute("SELECT domain FROM dead_domains LIMIT ? OFFSET ?", (limit, offset))
    else:
        c.execute("SELECT domain FROM dead_domains LIMIT ? OFFSET ?", (limit, offset))


    rows = c.fetchall()
    conn.close()

    html = f"""
    <html>
    <head>
        <title>Dead Domains</title>
        <style>
            table {{ border-collapse: collapse; width: 80%; margin: 20px auto; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            body {{ font-family: Arial, sans-serif; }}
            h1 {{ text-align: center; }}
            h2 {{ text-align: center; }}
            p {{ text-align: center; }}
            form {{ text-align: center; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        {get_navbar()}
        <h2>Processed Domains that did not resolve in DNS</h2>
        <form method="GET">
            <input type="hidden" name="search" value="true">
            <input type="text" name="domain" value="{domain_filter}" placeholder="Search Domain">
            <label for="limit">Rows per page:</label>
            <select name="limit">
                <option value="10" {"selected" if limit == 10 else ""}>10</option>
                <option value="25" {"selected" if limit == 25 else ""}>25</option>
                <option value="50" {"selected" if limit == 50 else ""}>50</option>
                <option value="100" {"selected" if limit == 100 else ""}>100</option>
            </select>
            <input type="submit" value="Apply">
        </form>
        <p><br><u>Total Rows:
        {total_rows}</u>
        </p>"""

    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&domain={domain_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"

    html+="""
    <table>
            <tr>
                <th>#</th>
                <th>IP</th>
            </tr>
    """
    i = 1
    for row in rows:
        html += f"<tr><td>{i}</td><td>{row[0]}</td></tr>"
        i=i+1
    html += "\n</table>\n"

    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&search={search_flag}&domain={domain_filter}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"

    return html

@app.route("/processed", methods=["GET"])
def processed():
    # Trying different logic to prevent the cluster of SELECT statements
    datatype_raw = request.args.get("type", "")
    datatype = re.sub(r"[^0-2]", "", datatype_raw)
    inscope_raw = request.args.get("fld_inscope", "")
    inscope = re.sub(r"[^0-2]", "", inscope_raw)
    search_raw = request.args.get("keyword", "")
    search = re.sub(r"[^A-Za-z0-9-.]", "", search_raw)
    tls_raw = request.args.get("tls_keyword", "")
    tls = re.sub(r"[^A-Za-z0-9-.]", "", tls_raw)
  
    # Both domain and IP
    type_filter = "%"
    if datatype == "0":
        type_filter = "IP_ADDRESS"
    elif datatype == "1":
        type_filter = "domain"
    
    inscope_filter = "%"
    if inscope == "0":
        inscope_filter = "0"
    if inscope == "1":
        inscope_filter = "1"
    
    search_filter = "%"
    if search:
        search_filter = search
    tls_filter = "%"
    if tls:
        tls_filter = tls
    
    limit = int(request.args.get("limit", 50))
    page = int(request.args.get("page", 1))
    offset = (page - 1) * limit

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    

    # First, get total rows for the current filter
    c.execute("SELECT COUNT(*) FROM processed WHERE fld_inscope LIKE ? AND type LIKE ? AND domainorip LIKE ? AND certdata LIKE ?", (inscope_filter, type_filter, f"%{search_filter}%", f"%{tls_filter}%"))
    total_rows = c.fetchone()[0]
    total_pages = math.ceil(total_rows / limit)

    c.execute("SELECT * FROM processed WHERE fld_inscope LIKE ? AND type LIKE ? AND domainorip LIKE ? AND certdata LIKE ? LIMIT ? OFFSET ?", (inscope_filter, type_filter, f"%{search_filter}%", f"%{tls_filter}%", limit, offset))
    
    rows = c.fetchall()
    conn.close()

    html = f"""
    <html>
    <head>
        <title>Processed Domains and IP Addresses</title>
        <style>
            table {{ border-collapse: collapse; width: 80%; margin: 20px auto; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            body {{ font-family: Arial, sans-serif; }}
            h1 {{ text-align: center; }}
            h2 {{ text-align: center; }}
            form {{ text-align: center; margin-bottom: 20px; }}
            p {{ text-align: center; }}
        </style>
    </head>
    <body>
        {get_navbar()}
        <h2>Processed Domains and IP Addresses</h2>
        <form method="GET", action="/processed">
            <input type="text" name="keyword" value="{search}" placeholder="Search Domain or IP">
            <input type="text" name="tls_keyword" value="{tls}" placeholder="Search TLS Data">
            <label for="limit">Rows per page:</label>
            <select name="limit">
                <option value="10" {"selected" if limit == 10 else ""}>10</option>
                <option value="25" {"selected" if limit == 25 else ""}>25</option>
                <option value="50" {"selected" if limit == 50 else ""}>50</option>
                <option value="100" {"selected" if limit == 100 else ""}>100</option>
            </select>
            
            <input type="submit" value="Apply">
            <br><br><b>Filter on domain or IP address:</b><br><br>
            <label><input type="radio" name="type" value="2" {"checked" if type_filter == "%" else ""}>Domains and IPs</label>
            <label><input type="radio" name="type" value="1" {"checked" if type_filter == "domain" else ""}>Domains</label>
            <label><input type="radio" name="type" value="0" {"checked" if type_filter == "IP_ADDRESS" else ""}>IP Addresses</label>
           
            <br><br><b>Filter on FLD in-scope</b><br><br>
            <label><input type="radio" name="fld_inscope" value="2" {"checked" if inscope_filter == "%" else ""}>Either</label>
            <label><input type="radio" name="fld_inscope" value="1" {"checked" if inscope_filter == "1" else ""}>In-Scope</label>
            <label><input type="radio" name="fld_inscope" value="0" {"checked" if inscope_filter == "0" else ""}>Not In-Scope</label>
        </form>
        <p><u>Total Rows:
        {total_rows}</u></p>
        """
    

    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&fld_inscope={inscope}&keyword={search}&tls_keyword={tls}&type={datatype}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"

    html +="""
        <table>
            <tr>
                <th>#</th>
                <th>Domain or IP</th>
                <th>Type</th>
                <th>FLD In Scope?</th>
                <th>TLS Data (CN,SAN,SAN,SAN...)</th>
            </tr>
    """
    i = 1
    for row in rows:
        html += f"<tr><td>{i}</td><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[4]}</td></tr>"
        i=i+1
    html += "\n</table>\n"

    # Pagination links
    html += "<div style='text-align:center; margin-top:20px;'>Pages: "
    for p in range(1, total_pages + 1):
        if p == page:
            html += f"<strong style='margin:0 5px;'>{p}</strong>"
        else:
            html += f"<a href='?page={p}&limit={limit}&fld_inscope={inscope}&keyword={search}&tls_keyword={tls}&type={datatype}' style='margin:0 5px;'>{p}</a>"
    html += "</div>"
    html += "\n</body>\n</html>"

    return html

@app.route("/export", methods=["POST","GET"])
def export():
    HTML_PAGE = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Export DB</title>
    </head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        h2 {{ text-align: center; }}
        form {{ text-align: center; margin-bottom: 20px; }}
    </style>
    <body>
        {get_navbar()}
        <h2>Export DNSscope DB to Excel</h2>
        <form action="/export" method="POST">
            <button type="submit">Export to Excel</button>
        </form>
    </body>
    </html>
    """
    if request.method == 'POST':
        db_path = "DNSscope.db"
        conn = sqlite3.connect(db_path)
        db = conn.cursor()
        # Create Excel workbook
        wb = Workbook()
        default_sheet = wb.active  # openpyxl creates a default sheet
        wb.remove(default_sheet)   # remove default sheet

        # Get all table names from SQLite
        db.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = db.fetchall()

        for (table_name,) in tables:
            # Create a new sheet for each table
            ws = wb.create_sheet(title=table_name)

            # Get column names
            db.execute(f"PRAGMA table_info({table_name})")
            columns = [col[1] for col in db.fetchall()]
            ws.append(columns)  # write header row

            # Get all rows
            db.execute(f"SELECT * FROM {table_name}")
            for row in db.fetchall():
                ws.append(row)

        # Save Excel file
        output_file = "DNSscope_export.xlsx"
        wb.save(output_file)

        # Close DB connection
        conn.close()

        # Save workbook to BytesIO
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)

        print(f"Export complete. Saved to {output_file}")
        return send_file(
        output,
        as_attachment=True,
        download_name="DNSscope_export.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        return HTML_PAGE


if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        print("Cannot find database file")
        exit(1)
    app.run(host="127.0.0.1", port=5432, debug=False)
