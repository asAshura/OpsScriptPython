# -*- coding:utf-8 -*-

"""
* Download Wangsu CDN log file
* "1. fetch the url of CDN download log,
*  which is between 'first day'-00:00:00 and 'last day'-00:00:00"
* "2. download log file"
* "3. upload log to S3 bucket"
"""

import datetime
import base64
import hashlib,hmac
import urllib2
import re
from config import AWSinfo, CDNinfo, EMAILinfo
import os,sys,threading
import boto3
import argparse
import logging
import smtplib
from email.mime.text import MIMEText

# import py_compile

__VERSION__ = '2018.01.04'
__DIR__ = sys.path[0]
__DELTADAY__ = 7

# py_compile.compile(os.path.join(__DIR__, 'config.py'))

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('[%(levelname)s] %(message)s')

# Create a file handler to store error messages
fhdr = logging.FileHandler(os.path.join(__DIR__, 'CDNlog.log'), mode='w')
fhdr.setLevel(logging.INFO)
fhdr.setFormatter(formatter)


logging.basicConfig(level=logging.INFO,
                format='%(asctime)s %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename=os.path.join(__DIR__, 'CDNlog.log'),
                filemode='w')
'''
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
'''
class ProgressPercentage(object):
    """the progress of log uploading to S3"""
    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()
    def __call__(self, bytes_amount):
        # To simplify we'll assume this is hooked up
        # to a single filename.
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                self._filename, self._seen_so_far, self._size,
                percentage))
            sys.stdout.flush()

def send_mail(mail_host, mail_user, mail_pass, to_list, sub, content):
    """send alarm email when download or upload fail"""
    me = "CDN log downloader" + "<" + mail_user + ">"
    msg = MIMEText(content, _subtype='plain', _charset='gb2312')
    msg['Subject'] = sub  # ....
    msg['From'] = me
    msg['To'] = ";".join([to_list])
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host, 465)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(me, to_list, msg.as_string())
        smtpObj.quit()
        return True
    except Exception, e:
        logging.error("Failed to send email\n")
        logging.error(e)
        return False



class CdnApi:
    """CdnApi class to manage Wangsu CDN API"""

    def __init__(self):
        self.username = CDNinfo['username']
        self.apiKey = CDNinfo['apiKey']
        self.date = datetime.datetime.today().strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.password = hmac.new(self.apiKey, self.date, hashlib.sha1).digest().encode('base64').rstrip()

    def _auth(self, url):
        """Authentication encryption"""
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, url, self.username, self.password)
        auth_handler = urllib2.HTTPDigestAuthHandler(password_mgr)
        return auth_handler

    def get_logurl(self, fday, lday, domain):
        """use the opener to fetch a URL for CDN log download"""
        url = 'https://open.chinanetcenter.com/api/report/log/downloadLink?datefrom=' + fday + 'T00:00:00%2B08:00&dateto=' + lday + "T00:00:00%2B08:00&filemd5=yes"
        _xml_parameters = '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><domain-list><domain-name>' + domain + '</domain-name></domain-list>'
        encodedstring = base64.encodestring(self.username + ":" + self.password)[:-1]
        auth = "Basic %s" % encodedstring
        headers = {"Authorization": auth,
               'Date': self.date,
               'Accept': 'application/json'}

        try:
            opener = urllib2.build_opener(self._auth(url))
            urllib2.install_opener(opener)
            req = urllib2.Request(url, _xml_parameters, headers)
            req.add_header('Content-Type', 'application/xml; charset=utf-8')
            req.add_header('Content-Length', len(_xml_parameters))
            cdn_info = urllib2.urlopen(req).read()
            if cdn_info.split("\"")[1] == "logs":
                return cdn_info
            else:
                logging.error("Unexpected CDN log url, Please check the CDN API. Return info is ", cdn_info)
        except urllib2.HTTPError, e:
            logging.error("can't fetch log url, http error is\n")
            logging.error(e)
            return False

def download_log(logurl, log_dir_name):
    try:
        f = urllib2.urlopen(logurl)
        # with open("/opt/cdn-log/"+log_dir_name, "wb") as code:
        with open(log_dir_name, "wb") as code:
            code.write(f.read())
    except Exception, e:
        logging.error("log download fail\n")
        logging.error(e)
        return False
    return True

def parse_cli_args():
    """Parser function"""
    ver = globals().get('__VERSION__')
    parser = argparse.ArgumentParser(
        description="starts the varnishncsa service with the parameters")
    parser.add_argument("-v", "--version", action='version',
                        version='%(prog)s  {version}'.format(version=ver))
    parser.add_argument("-f", "--fday", type=str,
                        help='Input the first day of CDN log in the format "yyyy-mm-dd"')
    parser.add_argument("-l", "--lday", type=str,
                        help='Input the last day of CDN log in the format "yyyy-mm-dd"')

    if len(sys.argv) < 2:
        # parser.exit()
        parser.print_usage()
    return parser.parse_args()

class AwsObject:
    def __init__(self):
        self.aws_access_key = AWSinfo['aws_access_key']
        self.aws_secret_key = AWSinfo['aws_secret_key']
        self.region_name = AWSinfo['region_name']
        self.metadata = AWSinfo['meta_url']

    def s3_upload(self, log_dir, log_name, directory):
        """upload log to S3"""
        try:
            s3_log = directory.format(log_name)
            log_dir_name = os.path.join(log_dir, log_name)
            s3 = boto3.client('s3', aws_access_key_id=self.aws_access_key, aws_secret_access_key=self.aws_secret_key, region_name=self.region_name)
            s3.upload_file(log_dir_name, "cdn-download-log", directory.format(log_name), Callback=ProgressPercentage(log_dir_name))
        except Exception, e:
            logging.error("log upload to S3 fail\n")
            logging.error(e)
            return False
        logging.info(log_dir_name + "log upload to S3 succeed\n")
        return True

    def get_ec2_ip(self):
        """return the ec2 IP"""
        f = urllib2.urlopen(self.metadata)
        return f.read()


def check_interval(fday, lday, today):
    """Check if the input interval is within 14 days and no later than today"""

    try:
        _sinterval = datetime.datetime.strptime(fday, "%Y-%m-%d")
        _linterval = datetime.datetime.strptime(lday, "%Y-%m-%d")

        days = (_linterval - _sinterval).days
        if days <= 13 and (today - _linterval).days >= 0 and _linterval >= _sinterval:
            return days
        else:
            return -1
    except:
        return -1

def remove_file(targetDir):
    for _file in os.listdir(targetDir):
        _target_file = os.path.join(targetDir, _file)
        _mtime = datetime.datetime.fromtimestamp(os.path.getmtime(_target_file))
        now = datetime.datetime.now()
        if (now - _mtime).days > __DELTADAY__:
            os.remove(_target_file)
            logging.info("\nRemove file " + _target_file + ", which time stamp is " + str(_mtime))

def main():
    sys.path.append(__DIR__)
    logging.info("\n")
    mailto_list = EMAILinfo['mailto_list']
    mail_host = EMAILinfo['mail_host']  # .....
    # mail_pop_host = EMAILinfo['mail_pop_host']
    mail_user = EMAILinfo['mail_user']  # ...
    mail_pass = EMAILinfo['mail_pass']  # ..
    # mail_postfix = EMAILinfo['mail_postfix']  # ......
    lday = datetime.datetime.today() + datetime.timedelta(hours=8)
    fday = (lday - datetime.timedelta(days=1))

    arg = parse_cli_args()
    days = check_interval(arg.fday, arg.lday, lday)
    if days == -1:
        logging.info("Didn't input the fday and lday right. Default time stamp of log will be yesterday 00:00:00 to 23:59:59.\n")
        days = (lday - fday).days
        fday = fday.strftime("%Y-%m-%d")
        lday = lday.strftime("%Y-%m-%d")
    else:
        fday = arg.fday
        lday = arg.lday


    vcc_directory = AWSinfo['vcc_directory']
    domain = CDNinfo['vcc_domain']

    cdn_log = CdnApi()
    aws = AwsObject()
    host_ip = aws.get_ec2_ip()

    log_info = cdn_log.get_logurl(fday, lday, domain)
    if log_info == False:
    # if log_info.split("\"")[1] != "logs":
        content = "\nFetch log url fail!\nPlease login " + host_ip + " to check cdn_log.log and save CDN log manually."
        send_mail(mail_host, mail_user, mail_pass, mailto_list, "CDN log download fail!", content)
        sys.exit(1)

    logging.info("CDN log url is: " + log_info)
    logging.info("Start to download " + str(days) + " days log, between " + fday + " and " + lday)

    for i in range(days):
        logurl = log_info.split("\"")[i * 14 + 19]
        pattern = re.compile(r'\d{4}-.+?gz')
        logname = pattern.search(logurl).group()
        log_dir_name = os.path.join(__DIR__, logname)
        logging.info("log " + str(i+1) + ": logname is " + logname + ", logurl is " + logurl)
        if False == download_log(logurl, log_dir_name):
            content = "\nCDN log file" + log_dir_name + "download fail!\nPlease login " + host_ip + " to check cdn_log.log and save CDN log manually."
            send_mail(mail_host, mail_user, mail_pass, mailto_list, "CDN log download fail!", content)
            sys.exit(1)
        if False == aws.s3_upload(__DIR__, logname, vcc_directory):
            content = "\nCDN log file" + log_dir_name + "upload fail!\nPlease login " + host_ip + "i to check cdn_log.log and save CDN log manually."
            send_mail(mail_host, mail_user, mail_pass, mailto_list, "CDN log download fail!", content)
            sys.exit(1)

    remove_file(__DIR__)

if __name__ == '__main__':
    main()

#data = open("/opt/cdn-log/"+logname, 'rb')
#data = open(logname, 'rb')
#s3.Bucket('my-bucket').put_object(Key=logname, Body=data)
# s3 = boto3.resource('s3')
# for bucket in s3.buckets.all():
#    print(bucket.name)
