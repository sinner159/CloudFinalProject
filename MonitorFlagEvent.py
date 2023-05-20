from ryu.controller.event import EventBase, EventReplyBase, EventRequestBase

class MonitorFlagEvent(EventBase):

    def __init__(self, *args, **kwargs):
        super(MonitorFlagEvent, self).__init__(*args, **kwargs)
    

class MonitorFlagEventRequest(EventRequestBase):

     def __init__(self, *args, **kwargs):
        super(MonitorFlagEventRequest, self).__init__(*args, **kwargs)
    
class MonitorFlagEventReply(EventReplyBase):

     def __init__(self, *args, **kwargs):
        super(MonitorFlagEventReply, self).__init__(*args, **kwargs)
    
