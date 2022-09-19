'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

'''
*******************************************************
**************  refactored by lawlez  *****************
*******************************************************
'''

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from cgi import FieldStorage
from requests.packages.urllib3 import disable_warnings
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python import log as tlog
from random import choice
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress

disable_warnings()


class QHTTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.key = path.join(gettempdir(), next(_get_candidate_names()))
        self.cert = path.join(gettempdir(), next(_get_candidate_names()))
        self.mocking_server = choice(['Apache', 'nginx', 'Microsoft-IIS/7.5', 'Microsoft-HTTPAPI/2.0', 'Apache/2.2.15', 'SmartXFilter', 'Microsoft-IIS/8.5', 'Apache/2.4.6', 'Apache-Coyote/1.1', 'Microsoft-IIS/7.0', 'Apache/2.4.18', 'AkamaiGHost', 'Apache/2.2.25', 'Microsoft-IIS/10.0', 'Apache/2.2.3', 'nginx/1.12.1', 'Apache/2.4.29', 'cloudflare', 'Apache/2.2.22'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 80
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def http_server_main(self):
        _q_s = self

        class MainResource(Resource):

            isLeaf = True

            home_file = b'''
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
    See: https://launchpad.net/bugs/1288690
  -->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
    <style type="text/css" media="screen">
  * {
    margin: 0px 0px 0px 0px;
    padding: 0px 0px 0px 0px;
  }

  body, html {
    padding: 3px 3px 3px 3px;

    background-color: #D8DBE2;

    font-family: Verdana, sans-serif;
    font-size: 11pt;
    text-align: center;
  }

  div.main_page {
    position: relative;
    display: table;

    width: 800px;

    margin-bottom: 3px;
    margin-left: auto;
    margin-right: auto;
    padding: 0px 0px 0px 0px;

    border-width: 2px;
    border-color: #212738;
    border-style: solid;

    background-color: #FFFFFF;

    text-align: center;
  }

  div.page_header {
    height: 99px;
    width: 100%;

    background-color: #F5F6F7;
  }

  div.page_header span {
    margin: 15px 0px 0px 50px;

    font-size: 180%;
    font-weight: bold;
  }

  div.page_header img {
    margin: 3px 0px 0px 40px;

    border: 0px 0px 0px;
  }

  div.table_of_contents {
    clear: left;

    min-width: 200px;

    margin: 3px 3px 3px 3px;

    background-color: #FFFFFF;

    text-align: left;
  }

  div.table_of_contents_item {
    clear: left;

    width: 100%;

    margin: 4px 0px 0px 0px;

    background-color: #FFFFFF;

    color: #000000;
    text-align: left;
  }

  div.table_of_contents_item a {
    margin: 6px 0px 0px 6px;
  }

  div.content_section {
    margin: 3px 3px 3px 3px;

    background-color: #FFFFFF;

    text-align: left;
  }

  div.content_section_text {
    padding: 4px 8px 4px 8px;

    color: #000000;
    font-size: 100%;
  }

  div.content_section_text pre {
    margin: 8px 0px 8px 0px;
    padding: 8px 8px 8px 8px;

    border-width: 1px;
    border-style: dotted;
    border-color: #000000;

    background-color: #F5F6F7;

    font-style: italic;
  }

  div.content_section_text p {
    margin-bottom: 6px;
  }

  div.content_section_text ul, div.content_section_text li {
    padding: 4px 8px 4px 16px;
  }

  div.section_header {
    padding: 3px 6px 3px 6px;

    background-color: #8E9CB2;

    color: #FFFFFF;
    font-weight: bold;
    font-size: 112%;
    text-align: center;
  }

  div.section_header_red {
    background-color: #CD214F;
  }

  div.section_header_grey {
    background-color: #9F9386;
  }

  .floating_element {
    position: relative;
    float: left;
  }

  div.table_of_contents_item a,
  div.content_section_text a {
    text-decoration: none;
    font-weight: bold;
  }

  div.table_of_contents_item a:link,
  div.table_of_contents_item a:visited,
  div.table_of_contents_item a:active {
    color: #000000;
  }

  div.table_of_contents_item a:hover {
    background-color: #000000;

    color: #FFFFFF;
  }

  div.content_section_text a:link,
  div.content_section_text a:visited,
   div.content_section_text a:active {
    background-color: #DCDFE6;

    color: #000000;
  }

  div.content_section_text a:hover {
    background-color: #000000;

    color: #DCDFE6;
  }

  div.validator {
  }
    </style>
  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/ubuntu-logo.png" alt="Ubuntu Logo" class="floating_element"/>
        <span class="floating_element">
          Apache2 Ubuntu Default Page
        </span>
      </div>
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>
-->
      <div class="content_section floating_element">


        <div class="section_header section_header_red">
          <div id="about"></div>
          It works!
        </div>
        <div class="content_section_text">
          <p>
                This is the default welcome page used to test the correct
                operation of the Apache2 server after installation on Ubuntu systems.
                It is based on the equivalent page on Debian, from which the Ubuntu Apache
                packaging is derived.
                If you can read this page, it means that the Apache HTTP server installed at
                this site is working properly. You should <b>replace this file</b> (located at
                <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.
          </p>


          <p>
                If you are a normal user of this web site and don't know what this page is
                about, this probably means that the site is currently unavailable due to
                maintenance.
                If the problem persists, please contact the site's administrator.
          </p>

        </div>
        <div class="section_header">
          <div id="changes"></div>
                Configuration Overview
        </div>
        <div class="content_section_text">
          <p>
                Ubuntu's Apache2 default configuration is different from the
                upstream default configuration, and split into several files optimized for
                interaction with Ubuntu tools. The configuration system is
                <b>fully documented in
                /usr/share/doc/apache2/README.Debian.gz</b>. Refer to this for the full
                documentation. Documentation for the web server itself can be
                found by accessing the <a href="/manual">manual</a> if the <tt>apache2-doc</tt>
                package was installed on this server.

          </p>
          <p>
                The configuration layout for an Apache2 web server installation on Ubuntu systems is as follows:
          </p>
          <pre>/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf
          </pre>
          <ul>
                        <li>
                           <tt>apache2.conf</tt> is the main configuration
                           file. It puts the pieces together by including all remaining configuration
                           files when starting up the web server.
                        </li>

                        <li>
                           <tt>ports.conf</tt> is always included from the
                           main configuration file. It is used to determine the listening ports for
                           incoming connections, and this file can be customized anytime.
                        </li>

                        <li>
                           Configuration files in the <tt>mods-enabled/</tt>,
                           <tt>conf-enabled/</tt> and <tt>sites-enabled/</tt> directories contain
                           particular configuration snippets which manage modules, global configuration
                           fragments, or virtual host configurations, respectively.
                        </li>

                        <li>
                           They are activated by symlinking available
                           configuration files from their respective
                           *-available/ counterparts. These should be managed
                           by using our helpers
                           <tt>
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2enmod">a2enmod</a>,
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2dismod">a2dismod</a>,
                           </tt>
                           <tt>
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2ensite">a2ensite</a>,
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2dissite">a2dissite</a>,
                            </tt>
                                and
                           <tt>
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2enconf">a2enconf</a>,
                                <a href="https://manpages.debian.org/cgi-bin/man.cgi?query=a2disconf">a2disconf</a>
                           </tt>. See their respective man pages for detailed information.
                        </li>

                        <li>
                           The binary is called apache2. Due to the use of
                           environment variables, in the default configuration, apache2 needs to be
                           started/stopped with <tt>/etc/init.d/apache2</tt> or <tt>apache2ctl</tt>.
                           <b>Calling <tt>/usr/bin/apache2</tt> directly will not work</b> with the
                           default configuration.
                        </li>
          </ul>
        </div>

        <div class="section_header">
            <div id="docroot"></div>
                Document Roots
        </div>

        <div class="content_section_text">
            <p>
                By default, Ubuntu does not allow access through the web browser to
                <em>any</em> file apart of those located in <tt>/var/www</tt>,
                <a href="https://httpd.apache.org/docs/2.4/mod/mod_userdir.html">public_html</a>
                directories (when enabled) and <tt>/usr/share</tt> (for web
                applications). If your site is using a web document root
                located elsewhere (such as in <tt>/srv</tt>) you may need to whitelist your
                document root directory in <tt>/etc/apache2/apache2.conf</tt>.
            </p>
            <p>
                The default Ubuntu document root is <tt>/var/www/html</tt>. You
                can make your own virtual hosts under /var/www. This is different
                to previous releases which provides better security out of the box.
            </p>
        </div>

        <div class="section_header">
          <div id="bugs"></div>
                Reporting Problems
        </div>
        <div class="content_section_text">
          <p>
                Please use the <tt>ubuntu-bug</tt> tool to report bugs in the
                Apache2 package with Ubuntu. However, check <a
                href="https://bugs.launchpad.net/ubuntu/+source/apache2">existing
                bug reports</a> before reporting a new bug.
          </p>
          <p>
                Please report bugs specific to modules (such as PHP and others)
                to respective packages, not to the web server itself.
          </p>
        </div>




      </div>
    </div>
    <div class="validator">
    <p>
      <a href="https://validator.w3.org/check?uri=referer"><img src="https://www.w3.org/Icons/valid-xhtml10" alt="Valid XHTML 1.0 Transitional" height="31" width="88" /></a>
    </p>
    </div>
  </body>
</html>'''

            login_file = b'''
<!DOCTYPE html>
<html>
   <head>
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.0.0-beta.3/css/bootstrap.min.css' />
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css' />
	  <meta http-equiv='content-type' content='text/html;charset=utf-8' />
	  <title>Login</title>
	  <style>body,html {height: 100%;}</style>
   </head>
   <body>
	  <div class='container-fluid h-100'>
		 <div class='row justify-content-center h-100 align-items-center'>
			<div class='col col-xl-3'>
			   <form id='login' action='' method='post'>
				  <div class='form-group'>
					 <input class='form-control form-control-sm' name='username' type='text' placeholder='username' id='username'>
				  </div>
				  <div class='form-group'>
					 <input class='form-control form-control-sm' name='password' type='password' placeholder='password' id='password'>
				  </div>
				  <div class='form-group'>
					 <button class='btn btn-default btn-sm btn-block' type='submit'>login</button>
				  </div>
			   </form>
			</div>
		 </div>
	  </div>
   </body>
</html>
'''

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def render(self, request):

                headers = {}
                client_ip = ""

                with suppress(Exception):
                    def check_bytes(string):
                        if isinstance(string, bytes):
                            return string.decode()
                        else:
                            return str(string)
                    for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                        headers.update({check_bytes(item): ','.join(map(check_bytes, value))})
                    headers.update({'method': check_bytes(request.method)})
                    headers.update({'uri': check_bytes(request.uri)})

                if 'fix_get_client_ip' in _q_s.options:
                    with suppress(Exception):
                        raw_headers = dict(request.requestHeaders.getAllRawHeaders())
                        if b'X-Forwarded-For':
                            client_ip = check_bytes(raw_headers[b'X-Forwarded-For'][0])
                        elif b'X-Real-IP':
                            client_ip = check_bytes(raw_headers[b'X-Real-IP'][0])

                if client_ip == "":
                    client_ip = request.getClientAddress().host

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})
                    else:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if _q_s.mocking_server != '':
                    request.responseHeaders.removeHeader('Server')
                    request.responseHeaders.addRawHeader('Server', _q_s.mocking_server)

                if request.method == b'GET' or request.method == b'POST':
                    _q_s.logs.info({'server': 'http_server', 'action': request.method.decode(), 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if request.method == b'GET':
                    if request.uri == b'/login.html':
                        if _q_s.username != '' and _q_s.password != '':
                            request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                            return self.login_file

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file

                elif request.method == b'POST':
                    self.headers = request.getAllHeaders()
                    if request.uri == b'/login.html' or b'/':
                        if _q_s.username != '' and _q_s.password != '':
                            form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })
                            if 'username' in form and 'password' in form:
                                username = self.check_bytes(form['username'].value)
                                password = self.check_bytes(form['password'].value)
                                status = 'failed'
                                if username == _q_s.username and password == _q_s.password:
                                    username = _q_s.username
                                    password = _q_s.password
                                    status = 'success'
                                _q_s.logs.info({'server': 'http_server', 'action': 'login', 'status': status, 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file
                else:
                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file

        reactor.listenTCP(self.port, Site(MainResource()))
        reactor.run()

    def run_server(self, process=False, auto=False):
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'http_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.http_server_main()

    def close_port(self):
        ret = close_port_wrapper('http_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('http_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get, post
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get('http://{}:{}'.format(_ip, _port), verify=False)
            post('http://{}:{}/login.html'.format(_ip, _port), data={'username': (None, _username), 'password': (None, _password)})


if __name__ == '__main__':
        config = {
         "port":80,
         "ip":"0.0.0.0",
         "username":"admin",
         "password":"admin",
         "log_file_name":"http.log",
         "max_bytes":10000,
         "backup_count":10,
         "options":["capture_commands","fix_get_client_ip"]
      }
        qhttpserver = QHTTPServer(ip="0.0.0.0", port=config['port'], username=config['username'], password=config["password"], options=config['options'], config=config)
        qhttpserver.run_server()
