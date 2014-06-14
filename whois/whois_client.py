"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

  Last edited by:  $Author$
              on:  $DateTime$
        Revision:  $Revision$
              Id:  $Id$
          Author:  Chris Wolf
"""
import socket
#import pdb


def enforce_ascii(a):
    if isinstance(a, str) or isinstance(a, unicode):
        # return a.encode('ascii', 'replace')
        r = ""
        for i in a:
            if ord(i) >= 128:
                r += "?"
            else:
                r += i
        return r
    else:
        return a


class NICClient(object):

    def __init__(self, whois_server):
        self.whois_server = whois_server

    def whois_ns(self, query):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        #print 'Performing the whois'
        #print 'parameters given:', query, hostname, flags
        #pdb.set_trace()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.whois_server, 43))
        #send takes bytes as an input
        queryBytes = (query + "\r\n").encode()
        s.send(queryBytes)
        #recv returns bytes
        #print s
        response = b''
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        #pdb.set_trace()
        #print 'response', response
        response = enforce_ascii(response)
        #print 'returning whois response'
        return response.decode()

    def whois_http(self, query):
        #todo: add http
        pass
   
    def whois_lookup(self, query):

        result = self.whois_ns(query)
        #print 'whois_lookup finished'
        return result