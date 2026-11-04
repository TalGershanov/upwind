
class Indicators:

    def __init__(self,text):
        self.email_text = text

    INDICATOR_MAP={}

    @classmethod
    def add_indicators(cls,name):
        def decorator(func):
            cls.INDICATOR_MAP[name] = func
            return func
        return decorator

    @add_indicators('Sender Authentication')
    def detect_sender_impersonation(self):
        # DMARC, SPF,DKIM
        pass

    @add_indicators('Suspicious links')
    def detect_suspicious_links(self):
        pass

    @add_indicators('Spoofed sender')
    def detect_spoofed_sender(self):
        pass

    @add_indicators('Suspicious wording')
    def detect_suspicious_wording(self):
        pass

    @add_indicators('Attachment analysis')
    def attachment_analysis(self):
        pass
