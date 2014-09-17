import logging

from gevent.server import DatagramServer
from beeswarm.shared.models.protocol_type import ProtocolType
from beeswarm.drones.honeypot.capabilities.handlerbase import HandlerBase

logger = logging.getLogger(__name__)

class Sip(HandlerBase, DatagramServer):
    
    def __init__(self, sessions, options, workdir):
        super(Sip, self).__init__(sessions, options, workdir)
        self.protocol_type = ProtocolType.UDP
        self.socket = None
        sessiondict = { }
    
    def handle_session(self, data, address):
        
        assert self.socket
        sessionkey = address[0] + ":" + str(address[1])
        
        ## Look in our map (ok python, dictionary) for session with our key
        #
        if sessionkey in sessiondict.keys():
            
            ## We already know this guy
            #
            session = sessiondict[sessionkey]
        
        else:
            
            ## noob, create a session for him/her
            #
            session = self.create_session(address)
            sessiondict[sessionkey] = session
            session.activity()
        
        ## Log to our session this SIP message
        #
        session.transcript_incoming(data)
        
        ## this regex will attempt to define a good SIP package ... we'll see how far this goes :)
        #
        package = re.compile("^[A-Z]+ sip:+.*^CSeq:.*\r?\n\r?\n$", re.MULTILINE|re.DOTALL)
        
        ## if we got a valid SIP package, send it to the parser, if we don't, we'll ignore the message
        #
        if package.search(data):
            
            ## ok - now to parse out all the stuff they've sent us
            #
            parsed = self.parseMessage(data)
            
            ## this could be a valid overall package, but not use we're working with yet.  If we don't know how to process, we'll send back a 400 Bad Request
            #
            valid = 0
            
            ## REGISTER
            #
            p = re.compile("^REGISTER .*")
            m = p.match(data)
            if m:
                valid = 1
                
                ## If Expires is set to 0, this is an unregister message
                #
                if parsed['expires'] == 'Expires: 0\n':
                    valid = 1
                    self.ProxyAuthRequired407(parsed, address, session)
                    session.connected = False
                
                ## else, this is a REGISTRATION message, which we don't actually support yet - sending 404
                #
                else:
                    self.NotFound404(parsed, address, session)
        
            ## INVITE
            #
            p = re.compile("^INVITE .*")
            m = p.match(data)
            if m:
                valid = 1
                self.ProxyAuthRequired407(parsed, address, session)
            
            ## Otherwise, send it back as Bad Requst
            #
            if valid == 0:
                self.BadRequest400(parsed, address, session)
    
    def parseMessage(self, data):
        
        response = { }
        
        # parsing out the max forwards
        maxforwards = ''
        p = re.compile(".*^(Max-Forwards: [^0-9]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            maxforwards = m.group(1) + '\n'
        response['maxforwards'] = maxforwards
        
        # parsing out the from address
        fromaddr = ''
        p = re.compile(".*^(From:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            fromaddr = m.group(1) + '\n'
        response['fromaddr'] = fromaddr
        
        # parsing out the to address
        toaddr = ''
        p = re.compile(".*^(To:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            toaddr = m.group(1) + '\n'
        response['toaddr'] = toaddr
        
        # parsing out the callid
        callid = ''
        p = re.compile(".*^(Call-ID: [^\n]+)$.*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            callid = m.group(1) + '\n'
        response['callid'] = callid
        
        # parsing out the cseq
        cseq = ''
        p = re.compile(".*^(CSeq: [0-9]+ [A-Z]+)$.*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            cseq = m.group(1) + '\n'
        response['cseq'] = cseq
        
        # parsing out the auth
        # parsing out the auth and a bunch of parameters that are encapsulated with it
        auth = ''
        p = re.compile(".*^Authorization: ([^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            auth = m.group(1) + ''
            response['auth'] = auth
            
            user = ''
            p = re.compile('Digest username="([^"]+)"')
            n = p.match(auth)
            if n:
                user = n.group(1)
            response['user'] = user
            
            realm = ''
            p = re.compile('.*realm="([^"]+)"')
            n = p.match(auth)
            if n:
                realm = n.group(1)
            response['realm'] = realm
            
            nonce = ''
            p = re.compile('.*nonce="([^"]+)"')
            n = p.match(auth)
            if n:
                nonce = n.group(1)
            response['nonce'] = nonce
            
            uri = ''
            p = re.compile('.*uri="([^"]+)"')
            n = p.match(auth)
            if n:
                uri = n.group(1)
            response['uri'] = uri
            
            resp = ''
            p = re.compile('.*response="([^"]+)"')
            n = p.match(auth)
            if n:
                resp = n.group(1)
            response['resp'] = resp
            
            cnonce = ''
            p = re.compile('.*cnonce="([^"]+)"')
            n = p.match(auth)
            if n:
                cnonce = n.group(1)
            response['cnonce'] = cnonce
            
            opaque = ''
            p = re.compile('.*opaque="([^"]+)"')
            n = p.match(auth)
            if n:
                opaque = n.group(1)
            response['opaque'] = opaque
            
            qop = ''
            p = re.compile('.*qop=([a-zA-Z0-9]+)')
            n = p.match(auth)
            if n:
                qop = n.group(1)
            response['qop'] = qop
            
            nc = ''
            p = re.compile('.*nc=([0-9]+)')
            n = p.match(auth)
            if n:
                nc = n.group(1)
            response['nc'] = nc
        
        response['auth'] = auth
        
        ## If we got a  user/response in auth, then log them
        #
        if 'user' in response.keys():
            if 'resp' in response.keys():
                session.try_auth('cram_md5', username=parsed['user'], digest=parsed['resp'])
        
        # parsing out the via
        via = ''
        p = re.compile(".*^(Via:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            via = m.group(1) + '\n'
        response['via'] = via
        
        # parsing out the contact
        contact = ''
        p = re.compile(".*^(Contact:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            contact = m.group(1) + '\n'
        response['contact'] = contact
        
        # parsing out the expires
        expires = ''
        p = re.compile(".*^(Expires: [0-9]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            expires = m.group(1) + '\n'
        response['expires'] = expires
        
        # parsing out the user agent
        ua = ''
        p = re.compile(".*^(User-Agent:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            ua = m.group(1) + '\n'
        response['ua'] = ua
        
        # parsing out the allows
        allow = ''
        p = re.compile(".*^(Allow:[^\n]+).*", re.MULTILINE|re.DOTALL);
        m = p.match(data)
        if m:
            allow = m.group(1) + '\n'
        response['allow'] = allow
        
        return response
    
    def ProxyAuthRequired407(self, params, address, session):
        message = 'SIP/2.0 100 Trying\n' + params['fromaddr'] + params['toaddr'] + params['callid'] + params['cseq'] + params['via'] + params['contact'] + 'Content-Length: 0\n\nSIP/2.0 407 Proxy authentication required\n' + params['fromaddr'] + params['toaddr'] + params['callid'] + params['cseq'] + params['via'] + params['contact'] + 'Allow: INVITE,BYE,INFO,PRACK,CANCEL,ACK,OPTIONS,SUBSCRIBE,NOTIFY,REGISTER,REFER,UPDATE\nContent-Length: 0\n\n'
        session.transcript_outgoing(message)
        self.socket.sendto(message, address)
    
    def NotFound404(self, params, address, session):
        message = ('SIP/2.0 404 Not found\n' + params['fromaddr'] + params['toaddr'] + params['callid'] + params['cseq']  + params['via'] + params['contact'] + params['expires'] + 'Allow: INVITE,BYE,INFO,PRACK,CANCEL,ACK,OPTIONS,SUBSCRIBE,NOTIFY,REFER,UPDATE,MESSAGE\nSupported: outbound,path\n' + params['ua'] + 'Content-Length: 0\n\n')
        session.transcript_outgoing(message)
        self.socket.sendto(message, address)
    
    def BadRequest400(self, params, address, session):
        message = 'SIP/2.0 400 Bad request\n' + params['via'] + params['maxforwards'] + params['fromaddr'] + params['toaddr'] + params['callid'] + params['cseq'] + params['ua'] + params['contact'] + params['expires'] + params['allow'] + 'Content-Length:  0'
        session.transcript_outgoing(message)
        self.socket.sendto(message, address)
