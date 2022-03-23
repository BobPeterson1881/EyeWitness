import http.client
import os
import socket
import sys
import urllib.request
import urllib.error
import urllib.parse
import ssl
import datetime
import OpenSSL.crypto as crypto

try:
    from ssl import CertificateError as sslerr
except:
    from ssl import SSLError as sslerr

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.common.exceptions import NoAlertPresentException
    from selenium.common.exceptions import TimeoutException
    from selenium.common.exceptions import UnexpectedAlertPresentException
    from selenium.common.exceptions import WebDriverException
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
except ImportError:
    print('[*] Selenium not found.')
    print('[*] Please run the script in the setup directory!')
    sys.exit()

from modules.helpers import do_delay

def create_driver(cli_parsed, user_agent=None):
    """Creates a selenium FirefoxDriver

    Args:
        cli_parsed (ArgumentParser): Command Line Object
        user_agent (String, optional): Optional user-agent string

    Returns:
        FirefoxDriver: Selenium Firefox Webdriver
    """
    profile = webdriver.FirefoxProfile()
    # Load our custom firefox addon to handle basic auth.
    extension_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', 'bin', 'dismissauth.xpi')
    profile.add_extension(extension_path)

    # This user agent case covers a user provided one
    if cli_parsed.user_agent is not None:
        profile.set_preference(
            'general.useragent.override', cli_parsed.user_agent)

    # This user agent case should only be hit when cycling
    if user_agent is not None:
        profile.set_preference('general.useragent.override', user_agent)

    # Set up our proxy information directly in the firefox profile
    if cli_parsed.proxy_ip is not None and cli_parsed.proxy_port is not None:
        profile.set_preference('network.proxy.type', 1)
        if "socks" in cli_parsed.proxy_type:
            profile.set_preference('network.proxy.socks', cli_parsed.proxy_ip)
            profile.set_preference('network.proxy.socks_port', cli_parsed.proxy_port)
        else:
            profile.set_preference('network.proxy.http', cli_parsed.proxy_ip)
            profile.set_preference(
                'network.proxy.http_port', cli_parsed.proxy_port)
            profile.set_preference('network.proxy.ssl', cli_parsed.proxy_ip)
            profile.set_preference('network.proxy.ssl_port', cli_parsed.proxy_port)

    profile.set_preference('app.update.enabled', False)
    profile.set_preference('browser.search.update', False)
    profile.set_preference('extensions.update.enabled', False)

    try:
        capabilities = DesiredCapabilities.FIREFOX.copy()
        capabilities.update({'acceptInsecureCerts': True})
        options = Options()
        options.add_argument("--headless")
        profile.update_preferences()
        driver = webdriver.Firefox(profile, capabilities=capabilities, options=options, service_log_path=cli_parsed.selenium_log_path)
        driver.set_page_load_timeout(cli_parsed.timeout)
        return driver
    except Exception as e:
        if 'Failed to find firefox binary' in str(e):
            print('Firefox not found!')
            print('You can fix this by installing Firefox/Iceweasel\
             or using phantomjs/ghost')
        else:
            print(e)
        sys.exit()


def capture_host(cli_parsed, http_object, driver, ua=None):
    """Screenshots a single host, saves information, and returns
    a complete HTTP Object

    Args:
        cli_parsed (ArgumentParser): Command Line Object
        http_object (HTTPTableObject): Object containing data relating to current URL
        driver (FirefoxDriver): webdriver instance
        ua (String, optional): Optional user agent string

    Returns:
        HTTPTableObject: Complete http_object
    """

    # Attempt to take the screenshot
    try:
        driver.get(http_object.remote_system)
    except KeyboardInterrupt:
        print('[*] Skipping: {0}'.format(http_object.remote_system))
        http_object.error_state = 'Skipped'
        http_object.page_title = 'Page Skipped by User'
    except TimeoutException:
        print('[*] Hit timeout limit when connecting to {0}, retrying'.format(http_object.remote_system))
        driver.quit()
        driver = create_driver(cli_parsed, ua)
        http_object.error_state = 'Timeout'
    except http.client.BadStatusLine:
        print('[*] Bad status line when connecting to {0}'.format(http_object.remote_system))
        http_object.error_state = 'BadStatus'
        return http_object, driver
    except WebDriverException:
        print('[*] WebDriverError when connecting to {0}'.format(http_object.remote_system))
        http_object.error_state = 'BadStatus'
        return http_object, driver

    # Dismiss any alerts present on the page
    # Will not work for basic auth dialogs!
    try:
        alert = driver.switch_to.alert
        alert.dismiss()
    except Exception as e:
        pass

    # If we hit a timeout earlier, retry once
    if http_object.error_state == 'Timeout':
        retry_counter = 0
        return_status = False
        while retry_counter < cli_parsed.max_retries:
            http_object.error_state = None
            try:
                driver.get(http_object.remote_system)
                break
            except TimeoutException:
                # Another timeout results in an error state and a return
                print('[*] Hit timeout limit when connecting to {0}'.format(http_object.remote_system))
                http_object.error_state = 'Timeout'
                http_object.page_title = 'Timeout Limit Reached'
                http_object.headers = {}
                driver.quit()
                driver = create_driver(cli_parsed, ua)
                return_status = True
            except KeyboardInterrupt:
                print('[*] Skipping: {0}'.format(http_object.remote_system))
                http_object.error_state = 'Skipped'
                http_object.page_title = 'Page Skipped by User'
                break
            except http.client.BadStatusLine:
                print('[*] Bad status line when connecting to {0}'.format(http_object.remote_system))
                http_object.error_state = 'BadStatus'
                return_status = True
                break
            except WebDriverException:
                print('[*] WebDriverError when connecting to {0}'.format(http_object.remote_system))
                http_object.error_state = 'BadStatus'
                return_status = True
                break
            retry_counter += 1

        # Determine if I need to return the objects
        if return_status:
            return http_object, driver

        try:
            alert = driver.switch_to.alert
            alert.dismiss()
        except Exception as e:
            pass

    do_delay(cli_parsed)

    # Save our screenshot to the specified directory
    try:
        driver.save_screenshot(http_object.screenshot_path)
    except WebDriverException as e:
        print('[*] Error saving web page screenshot'
              ' for ' + http_object.remote_system)

    # Get our headers using urllib
    context = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    except:
        context = None
        pass

    try:
        tempua = driver.execute_script("return navigator.userAgent")
    except:
        tempua = ''
    try:
        req = urllib.request.Request(http_object.remote_system, headers={'User-Agent': tempua})
        if cli_parsed.proxy_ip is not None:
            req.set_proxy(str(cli_parsed.proxy_ip) + ':' + str(cli_parsed.proxy_port), 'http')
            req.set_proxy(str(cli_parsed.proxy_ip) + ':' + str(cli_parsed.proxy_port), 'https')
        if context is None:
            opened = urllib.request.urlopen(req)
        else:
            opened = urllib.request.urlopen(req, context=context)
        headers = dict(opened.info())
        headers['Response Code'] = str(opened.getcode())
    except urllib.error.HTTPError as e:
        responsecode = e.code
        if responsecode == 404:
            http_object.category = 'notfound'
        elif responsecode == 403 or responsecode == 401:
            http_object.category = 'unauth'
        elif responsecode == 500:
            http_object.category = 'inerror'
        elif responsecode == 400:
            http_object.category = 'badreq'
        headers = dict(e.headers)
        headers['Response Code'] = str(e.code)
    except urllib.error.URLError as e:
        if '104' in str(e.reason):
            headers = {'Error': 'Connection Reset'}
            http_object.error_state = 'ConnReset'
            return http_object, driver
        elif '111' in str(e.reason):
            headers = {'Error': 'Connection Refused'}
            http_object.error_state = 'ConnRefuse'
            return http_object, driver
        elif 'Errno 1' in str(e.reason) and 'SSL23' in str(e.reason):
            headers = {'Error': 'SSL Handshake Error'}
            http_object.error_state = 'SSLHandshake'
            return http_object, driver
        elif 'Errno 8' in str(e.reason) and 'EOF occurred' in str(e.reason):
            headers = {'Error': 'SSL Handshake Error'}
            http_object.error_state = 'SSLHandshake'
            return http_object, driver
        else:
            headers = {'Error': 'HTTP Error...'}
            http_object.error_state = 'BadStatus'
            return http_object, driver
    except socket.error as e:
        if e.errno == 104:
            headers = {'Error': 'Connection Reset'}
            http_object.error_state = 'ConnReset'
            return http_object, driver
        elif e.errno == 10054:
            headers = {'Error': 'Connection Reset'}
            http_object.error_state = 'ConnReset'
            return http_object, driver
        else:
            http_object.error_state = 'BadStatus'
            return http_object, driver
    except http.client.BadStatusLine:
        http_object.error_state = 'BadStatus'
        return http_object, driver
    except sslerr:
        headers = {'Error': 'Invalid SSL Certificate'}
        http_object.ssl_error = True

    # Get certificate information if requested
    if (cli_parsed.cert_info) and ('https' in http_object.remote_system): 
        
        #Extract hostname and port from remote_system object
        url=urllib.parse.urlparse(http_object.remote_system)
        host=url.hostname

        if url.port is not None:
            port=url.port 
        else:
            port=443

        try:
            conn = socket.create_connection((host, port))
            sock = context.wrap_socket(conn, server_hostname=host)
            cert = sock.getpeercert(True)

            #Convert the cert to x509 so we can parse.
            x509=crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
            now = datetime.datetime.now()
            begin = datetime.datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
            begin_ok = begin < now
            end = datetime.datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
            end_ok = end > now
            if end_ok:
                days_to_expire="{} days".format((end-now).days)
            else:
                days_to_expire="Expired"

            alt_name=''
            for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    ext_name = ext.get_short_name().decode()
                    if ext_name == "subjectAltName":
                        alt_name=ext._subjectAltNameString()




            subject_components=[(z[0].decode(),z[1].decode()) for z in x509.get_subject().get_components()]
            issuer_components=[(z[0].decode(),z[1].decode()) for z in x509.get_issuer().get_components()]

            cert_info = {
                'subject': dict(subject_components),
                'issuer': dict(issuer_components),
                'altNames':alt_name,
                'serialNumber': x509.get_serial_number(),
                'version': x509.get_version(),
                'notBefore': begin,
                'notAfter': end,
                'daysToExpire': days_to_expire
            }

            #append cert info to the object
            http_object.cert_info = cert_info

        except socket.error as e:
            if e.errno == 104:
                print("Error:  Connection Reset")
            elif e.errno == 10054:
                print("Error:  Connection Reset")
            else:
                print("Error:  Bad Status")
                print(e)
        except Exception as e:
            print("Something went wrong")
            print(e)
                

    try:
        http_object.page_title = 'Unknown' if driver.title == '' else driver.title.encode(
            'utf-8')
    except Exception:
        http_object.page_title = 'Unable to Display'
    # Save page source to the object and to a file. Also set the title in the object
    try:
        http_object.headers = headers
        http_object.source_code = driver.page_source.encode('utf-8')
        with open(http_object.source_path, 'w') as f:
            f.write(http_object.source_code.decode())
    except UnexpectedAlertPresentException:
        with open(http_object.source_path, 'w') as f:
            f.write('Cannot render webpage')
        http_object.headers = {'Cannot Render Web Page': 'n/a'}
    except IOError:
        print("[*] ERROR: URL too long, surpasses max file length.")
        print("[*] ERROR: Skipping: " + http_object.remote_system)
    except WebDriverException:
        print("[*] ERROR: Skipping source code capture for: " + http_object.remote_system)

    return http_object, driver
