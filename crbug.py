# coding:utf-8

import re
import json
import pickle
import os
import sys
import socket

# Set timeout to 10s.
socket.setdefaulttimeout(10)

from urllib.request import urlopen, Request, HTTPError

from bs4 import BeautifulSoup

BLOG_URL = r'https://chromereleases.googleblog.com/'
TITLE = r'Stable Channel Update for Desktop'
MAX_POSTS = 2000
MAX_ISSUE_CHECK_RANGE =  200000 # Issues too old may close forever, so skip check them.

CRBUG_URL = r'https://crbug.com/'
GETISSUE_URL = r"https://bugs.chromium.org/prpc/monorail.Issues/GetIssue"
LISTCOMMENT_URL = r"https://bugs.chromium.org/prpc/monorail.Issues/ListComments"

MD_PATH = './crbug.md'
DB_PATH = './db.pickle'

class Log:
    def i(self, msg):
        print('[+] %s' % msg)
    
    def d(self, msg):
        print('[*] %s' % msg)

    def e(self, msg):
        print('[!] %s' % msg)

    def scroll(self, count, max):
        sys.stdout.write('-- %s/%s ... \r' % (count, max))

log = Log()

def httpGet(url):
    try:
        return urlopen(url).read()
    except Exception as e:
        print("[!] Http GET Error: %s" % e)
        return None


def httpPost(url, data=None, headers={}):
    try:
        r = Request(url, data, headers)
        return urlopen(r).read()
    except Exception as e:
        print("[!] Http POST Error: %s" % e)
        return None

TOKEN = re.findall("'token': '(.*?)'", httpGet(CRBUG_URL).decode())[0]

def crbugPost(id, url):
    data = r'{"issueRef":{"localId":%s,"projectName":"chromium"}}' % id
    headers = {
        "accept": "application/json",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "x-xsrf-token": TOKEN
    }
    r = httpPost(url, data.encode(), headers)
    if r:
        # eg: ')]}\'\n{\n  "issue": {\n ....
        r = json.loads(r.decode('utf-8')[5:])
    return r

def getCrBugIssue(id):
    return crbugPost(id, GETISSUE_URL)

def getCrBugComment(id):
    return crbugPost(id, LISTCOMMENT_URL)

assert getCrBugIssue(944971), "Wrong token."

class Issue(object):

    def __init__(self, id):
        self.id = id
        self.url = CRBUG_URL + str(id)
        self.update()
        log.d('Add new issue: %s' % self)
    
    def update(self):
        issue = getCrBugIssue(self.id)
        if issue:
            self.open = True
            self.summary = issue["issue"]["summary"]
            self.reporter = issue["issue"]["reporterRef"]["displayName"]
            comments = getCrBugComment(self.id)
            if comments:
                self.content = comments["comments"][0]["content"]
            else:
                log.e('Issue %s %s opened but not comments found.' % (self.id, self.url))
                self.content = None
                self.open = False
        else:
            self.open = False

    def __repr__(self):
        if self.open:
            return 'Issue %s: %s (%s)' % (self.id, self.summary, self.reporter)
        else:
            return 'Issue %s (Permission denied.)' % (self.id)
    
    def _escape(self, s):
        s = s.replace('<', r'\<')
        s = s.replace('>', r'\>')
        return s

    def __str__(self):
        if self.open:
            return '[Issue %s: %s (%s)](%s)' % (self.id, self._escape(self.summary), self.reporter, self.url)
        else:
            return '[Issue %s (Permission denied.)](%s)' % (self.id, self.url)        

class BugBase(object):

    def __init__(self, id):
        self.id = id

    def toJson(self):
        return json.dumps(self.__dict__)

    def fromJson(self, s):
        self.__dict__ = json.loads(s)

    def fromDict(self, d):
        self.__dict__ = d

    def checkIssueStatus(self):        
        return getCrBugIssue(self.id) != None

class CveBug(BugBase):

    # eg: [$N/A][1073602] High CVE-2020-6831: Stack buffer overflow in SCTP. Reported by Natalie Silvanovich of Google Project Zero on 2020-04-22
    PATTERN = r'\[(.*?)\]\[(\d*?)\] (.*?) (.*?): (.*?) Reported by (.*?) on (\d+-\d+-\d+)'

    # used before 2017/05
    # eg: [$8837][671102] High CVE-2017-5007: Universal XSS in Blink. Credit to Mariusz Mlynski
    PATTERN_OLD = r'\[(.*?)\]\[(\d*?)\] (.*?) (.*?): (.*?) Credit to (.*)\n?'

    def __init__(self, items):
        self.award = items[0]
        self.id = items[1]
        self.level = items[2]
        self.cve = items[3]
        self.summary = items[4]
        self.reporter = items[5]
        self.date = items[6]
        self.url = CRBUG_URL + self.id
        self.issue = Issue(self.id)

    def __repr__(self):
        return '[%s][%s] %s %s: %s Reported by %s on %s' % (
            self.award,
            self.id,
            self.level,
            self.cve,
            self.summary,
            self.reporter,
            self.date
        )

    def __str__(self):
        return '[%s][[%s](%s)] %s %s: %s Reported by %s on %s\n\t- %s' % (
            self.award,
            self.id,
            self.url,
            self.level,
            self.cve,
            self.summary,
            self.reporter,
            self.date,
            self.issue
        )


class InternalBug(BugBase):

    # eg: [1057473] Various fixes from internal audits, fuzzing and other initiatives
    PATTERN = r'\[(\d*?)\] Various fixes from internal audits, fuzzing and other initiatives'

    def __init__(self, bugId):
        self.id = bugId
        self.issue = Issue(bugId)
        self.url =  CRBUG_URL + self.id
        self.issues = []
        self.getSubIssues()        

    def __repr__(self):
        return '[%s] internal.' % (self.id)

    def __str__(self):
        buf = '[[%s](%s)] internal.\n' % (
            self.id, 
            self.url)
        for issue in self.issues:
            buf += '\t- %s\n' % issue
        return buf

    def getSubIssues(self):
        if self.issue.open:
            bugIds = re.findall(CRBUG_URL + r'(\d+)', self.issue.content)
            for id in bugIds:
                self.issues.append(Issue(id))

class Post(object):

    def __init__(self, tag=None):
        self.title = None
        self.version = None
        self.time = None
        self.url = None
        self.bugs = []
        self.bug_count = 0


        if tag:
            self.parse(tag)

    @property
    def parsed_bug_count(self):
        n = 0
        for bug in self.bugs:
            if isinstance(bug, CveBug):
                n += 1
            elif isinstance(bug, InternalBug):
                n += len(bug.issues)
        return n

    def parse(self, tag):
        self.title = tag.h2.text.strip()
        self.time = tag.div.text.strip()
        self.url = tag.select('.title')[0].a["href"]

        ver = re.findall(r'Chrome ([\d\.]+?) contains a number of fixes and improvements', tag.text)
        ver += re.findall(r'The stable channel has been updated to ([\d\.]+?) for Windows', tag.text)
        if ver:
            self.version = ver[0]

        bugCount = re.findall(
            r'This update includes (\d+) security fix', tag.text)
        if bugCount:
            self.bug_count = bugCount[0]

        parsed_set = set()
        links = tag.select('a')
        for link in links:
            if "href" in link.attrs:
                link_url = link["href"]  # eg: https://crbug.com/1073602
                if CRBUG_URL in link_url and link.text in link_url:
                    self.parseBug(link.parent, parsed_set)

    def addBug(self, bug):        
        log.d('Add new bug: %s' % repr(bug))
        self.bugs.append(bug)

    def parseBug(self, tag, parsed_set=None):
        if parsed_set is not None: # Avoid parsing a same tag multi times.
            if tag in parsed_set:
                return
            else:
                parsed_set.add(tag)

        text = tag.text.strip()
        crbugs = re.findall(CveBug.PATTERN, text)
        for items in crbugs:
            bug = CveBug(items)
            self.addBug(bug)

        crbugs = re.findall(CveBug.PATTERN_OLD, text)
        for items in crbugs:
            items_ = list(items)
            items_.append(None)
            bug = CveBug(items_)
            self.addBug(bug)

        interbugs = re.findall(InternalBug.PATTERN, text)
        for bugId in interbugs:
            bug = InternalBug(bugId)
            self.addBug(bug)

    def __repr__(self):
        return r'%s (%s) [%s/%s bugs]' % (self.version, self.time, self.parsed_bug_count, self.bug_count)

    def toMarkDown(self):
        buf = '# %s(%s)\n' % (repr(self), self.url)
        for bug in self.bugs:
            buf += '- %s\n' % (bug)
        buf += '\n'
        return buf

class DataBase(object):

    def __init__(self):
        self.posts = []
        self.posts_new = []

        self.urls = {}
        self.vers = {}
        self.bugs = {}
        self.issues = {}

        self.load()

    def parsePage(self, url, loop=False, update=False):
        while True:
            if len(self.posts) >= MAX_POSTS:
                break

            page = httpGet(url)
            soup = BeautifulSoup(page, "html.parser")
            posts_tags = soup.select('.post')
            for tag in posts_tags:
                title = tag.h2.text.strip()
                if title == TITLE:
                    post_url = tag.select('.title')[0].a["href"]
                    if post_url in self.urls:
                        if update: # Stop when we met parsed page.
                            return
                        else:
                            continue
                        
                    post = Post(tag)
                    self.addPost(post, update)

            if loop:  # Parse next page.
                url = soup.select('.blog-pager-older-link')[0]["href"]
            else:
                break

    def addPost(self, post, update=False):
        if update:
            self.posts_new.append(post)
        else:
            self.posts.append(post)

        self.initIndex(post)
        log.i('%d %s' % (len(self.posts) + len(self.posts_new), repr(post)))

    def initIndex(self, post):
            self.vers[post.version] = post
            self.urls[post.url] = post
            for bug in post.bugs:
                self.bugs[bug.id] = bug
                self.issues[bug.issue.id] = bug.issue
                if isinstance(bug, InternalBug):
                    for issue in bug.issues:
                        self.issues[issue.id] = issue

    def load(self):
        if not os.path.exists(DB_PATH):
            log.i('No database found. Update now.')
            global MAX_POSTS
            MAX_POSTS = 200  # Only download 200 posts for the initial database creation.   
            self.parsePage(BLOG_URL, True)
            return
      
        f = open(DB_PATH, 'rb')
        self.posts = pickle.load(f)
        f.close()
    
        for post in self.posts:
            self.initIndex(post)

        log.i('%s posts, %s cves, %s issues loaded.' % (len(self.posts), len(self.bugs), len(self.issues)))

    def save(self):
        f = open(DB_PATH, 'wb')
        pickle.dump(self.posts, f)
        f.close()
        log.i('Save db to %s.' % DB_PATH)

    def update(self, force=False):
        self.posts_new = []
        self.parsePage(BLOG_URL, True, True)
        self.posts = self.posts_new + self.posts
        log.i('Updated. Found %s new post(s).' % len(self.posts_new))

    def updateIssues(self):
        issues = list(self.issues.values())
        issues = list(filter(lambda x: x.open == False, issues))
        if len(issues) == 0:
            log.i("No issues to update.")
            return

        log.i('%s issues are still restricted.' % len(issues))
        issues.sort(key=lambda i: int(i.id), reverse=True)
        
        end_id = int(issues[0].id) - MAX_ISSUE_CHECK_RANGE
        count = 0
        i = 0
        for issue in issues:
            if int(issue.id) < end_id:
                log.i('Stop at (%s) %s' % (i, repr(issue)))
                break

            log.scroll(i, len(issues))
            i +=1 

            issue.update()
            if issue.open:
                log.i('Open: %s' % repr(issue))
                count += 1

        log.i('%s issues opened.' % count)

    def saveToMD(self):
        md = open(MD_PATH, 'wb')
        for post in self.posts:
            md.write(post.toMarkDown().encode('utf-8'))
            md.flush()
        md.close()
        log.i('Save markdown to %s.' % MD_PATH)


if __name__ == '__main__':
    
    db = DataBase()
    db.update()
    db.save()
    db.saveToMD()
    db.updateIssues()
    db.save()
    db.saveToMD()