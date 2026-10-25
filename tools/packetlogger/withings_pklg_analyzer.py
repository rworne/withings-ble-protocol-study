#!/usr/bin/env python3
"""Offline, read-only Apple PacketLogger .pklg -> Withings BLE protocol timeline.
No external dependencies. Sensitive values are redacted by default.
"""
import argparse, collections, datetime, json, struct, pathlib, re, os

COMMANDS={0x0100:'protocol error/status',0x0101:'device identification',0x0102:'Wi-Fi scan',0x0103:'Wi-Fi credentials',0x0105:'battery information',0x0108:'region',0x0109:'Wi-Fi-related operation (unresolved)',0x010D:'primary JSON configuration',0x010F:'measurement inventory',0x0110:'setup completion',0x0111:'connection reason',0x0112:'setup stage',0x0113:'setup stage',0x011A:'language',0x0128:'challenge-response authentication',0x0131:'unresolved',0x0134:'ownership credentials',0x0147:'next pending binary signal',0x0148:'acknowledge signal / advance queue',0x0501:'set time',0x0502:'clock drift',0x09B2:'initial provisioning negotiation',0x09C1:'negotiation continuation',0x09C3:'secondary configuration'}
ATT={0x02:'exchange MTU request',0x03:'exchange MTU response',0x04:'find information request',0x05:'find information response',0x08:'read by type request',0x09:'read by type response',0x0A:'read request',0x0B:'read response',0x10:'read by group request',0x11:'read by group response',0x12:'write request',0x13:'write response',0x1B:'notification',0x1D:'indication',0x1E:'confirmation',0x52:'write command',0x01:'error response'}

def records(path):
    b=path.read_bytes(); off=0; idx=0
    while off+13<=len(b):
        n=int.from_bytes(b[off:off+4],'little')
        if n<9 or off+4+n>len(b):
            raise ValueError(f'Invalid PacketLogger record at offset {off} (size {n})')
        ts=int.from_bytes(b[off+4:off+8],'little')+int.from_bytes(b[off+8:off+12],'little')/1e6
        yield idx,ts,b[off+12],b[off+13:off+4+n]
        off+=4+n;idx+=1
    if off!=len(b): raise ValueError(f'{len(b)-off} trailing bytes')

def mac(a): return ':'.join(f'{x:02X}' for x in a[::-1])
def safe_mac(s):return ':'.join(s.split(':')[:3]+['XX','XX','XX']) if s else None

def ad_fields(data):
    out=[];p=0
    while p<len(data):
        n=data[p];p+=1
        if not n:break
        if p+n>len(data):break
        out.append((data[p],data[p+1:p+n]));p+=n
    return out

def scrub_json(obj):
    # Strict allowlist: even unknown nested string fields may contain secrets.
    if isinstance(obj,list): return [scrub_json(v) for v in obj]
    if isinstance(obj,dict):
        out={}
        for k,v in obj.items():
            if k.lower() in {'ft','mcr','model','version'} and isinstance(v,(int,bool,list)):
                out[k]=scrub_json(v) if isinstance(v,list) else v
            elif isinstance(v,(dict,list)):
                out[k]=scrub_json(v)
            else: out[k]='<redacted>'
        return out
    return obj if isinstance(obj,(int,float,bool)) else '<redacted>'

def tlvs(data, private=False):
    o=0;items=[]
    while o+4<=len(data):
        t=int.from_bytes(data[o:o+2],'big');n=int.from_bytes(data[o+2:o+4],'big');o+=4
        if o+n>len(data):return items,False
        val=data[o:o+n];o+=n
        d={'type':f'0x{t:04X}','length':n}

        if t==0x0135:
            d['meaning']='account identifier and KL'
            if n>=5:
                kl_length=val[4]
                d['account_id_format']='big-endian uint32'
                d['kl_length']=kl_length
                d['structure_valid']=(n==5+kl_length)
            else:
                d['structure_valid']=False
            if not private:
                d['account_id']='<redacted>'
                d['kl']='<redacted>'

        elif t==0x0136:
            d['meaning']='advertiser key'
            if n>=1:
                key_length=val[0]
                d['key_length']=key_length
                d['structure_valid']=(n==1+key_length)
            else:
                d['structure_valid']=False
            if not private:
                d['advertiser_key']='<redacted>'

        elif t==0x09D5 and n>=12:
            d['feature_id']=int.from_bytes(val[8:10],'big');d['feature_value']=int.from_bytes(val[10:12],'big')
        elif t==0x0116 and n==23 and private:
            d['signal_id']=int.from_bytes(val[:4],'big');d['parent_measurement_id']=int.from_bytes(val[19:23],'big')
        elif t==0x0145 and n==4:
            d['target']='global (0)' if not any(val) else (int.from_bytes(val,'big') if private else '<user-id-redacted>')
        elif t==0x0100 and n==0:d['meaning']='empty control/status'
        else:
            if not private: d['value']='<redacted>' if n else ''
        if private:
            d['value_hex']=val.hex()
            d['value']=val.decode('utf-8', errors='replace') if val else ''
        items.append(d)
    return items,o==len(data)

def parse_wpp(value, private=False):
    if len(value)<5 or value[0]!=1:return None
    cmd=int.from_bytes(value[1:3],'big');size=int.from_bytes(value[3:5],'big')
    if size>65535:return None
    if len(value)<5+size:
        partial={'command':f'0x{cmd:04X}','meaning':COMMANDS.get(cmd,'unknown'),'declared_length':size,'available_length':len(value)-5,'incomplete':True}
        if private:
            partial['frame_hex']=value.hex()
            partial['partial_payload_hex']=value[5:].hex()
        return partial
    payload=value[5:5+size]
    entry={'command':f'0x{cmd:04X}','meaning':COMMANDS.get(cmd,'unknown'),'declared_length':size}
    if len(value)>5+size:entry['trailing_bytes']=len(value)-5-size
    if private:
        entry['frame_hex']=value.hex()
        entry['payload_hex']=payload.hex()
    fields,valid=tlvs(payload, private=private)
    entry['tlvs']=fields;entry['tlv_complete']=valid
    return entry

class WPPStream:
    """Accumulate a WPP byte stream across ATT values, per (connection,direction,attribute).

    A malformed frame or an interrupted sequence is surfaced as a warning rather
    than silently fabricated into a complete message.
    """
    def __init__(self, private=False):
        self.buffer=bytearray()
        self.private=private
        self.start_record=None

    def feed(self, data, record):
        result=[]
        if not data: return result
        if not self.buffer: self.start_record=record
        self.buffer.extend(data)
        while len(self.buffer)>=5:
            if self.buffer[0]!=1:
                # Cannot trust a stream after loss of framing; resynchronize.
                next_start=self.buffer.find(1,1)
                dropped=len(self.buffer) if next_start<0 else next_start
                result.append({'warning':'invalid WPP prefix / resynchronizing',
                               'dropped_bytes':dropped,'start_record':self.start_record})
                del self.buffer[:dropped]
                self.start_record=record
                if not self.buffer: break
                continue
            size=int.from_bytes(self.buffer[3:5],'big')
            total=5+size
            if len(self.buffer)<total:break
            frame=bytes(self.buffer[:total]);del self.buffer[:total]
            parsed=parse_wpp(frame,private=self.private)
            if parsed:
                parsed['start_record']=self.start_record
                parsed['end_record']=record
                result.append(parsed)
            self.start_record=record
        return result

    def pending(self):
        return len(self.buffer)



def reconstruct_configuration_transfers(events, private=False):
    """Group 0x010D / 0x0112 WPP chunks until 0x0100, per connection/direction.

    Preserve original frame-level timeline; never infer missing bytes. A complete
    transfer is not considered acknowledged until a subsequent empty device reply.
    """
    active = {}
    awaiting_ack = {}
    transfers = []
    for event in events:
        handle = event['handle']
        direction = event['direction']
        for message in event.get('wpp_messages', []):
            if message.get('command') != '0x010D':
                continue
            key = (handle, direction)
            # The device's zero-length 0x010D reply acknowledges a completed
            # host-to-device configuration transfer on the same connection.
            if direction == 'device_to_host' and message.get('declared_length') == 0:
                pending = awaiting_ack.pop(handle, None)
                if pending is not None:
                    pending['acknowledged'] = True
                    pending['ack_record'] = event['record']
                continue
            fields = message.get('tlvs', [])
            for field in fields:
                kind = field['type']
                if kind == '0x0112':
                    state = active.get(key)
                    if state is None:
                        state = {'command': '0x010D', 'handle': handle,
                                 'direction': direction,
                                 'start_record': message['start_record'],
                                 'end_record': message['end_record'],
                                 'chunks': 0, 'wire_chunk_bytes': 0, 'assembled_length': 0,
                                 'terminated': False, 'acknowledged': False,
                                 'warnings': [], '_parts': []}
                        active[key] = state
                    state['chunks'] += 1
                    state['wire_chunk_bytes'] += field['length']
                    # 0x0112 chunk value is length-prefixed (one byte).
                    # Preserve uncertainty if a capture violates this layout.
                    if private:
                        raw_chunk = bytes.fromhex(field['value_hex'])
                        valid_chunk = bool(raw_chunk) and raw_chunk[0] == len(raw_chunk)-1
                    else:
                        # Public mode has no raw payload; 64/2 byte chunks
                        # in this capture use the same 1-byte prefix.
                        valid_chunk = field['length'] >= 1
                    if not valid_chunk:
                        state['warnings'].append('unexpected 0x0112 chunk length prefix')
                    state['assembled_length'] += max(0, field['length'] - 1)
                    state['end_record'] = message['end_record']
                    if private:
                        state['_parts'].append(raw_chunk[1:] if valid_chunk else raw_chunk)
                elif kind == '0x0100' and field['length'] == 0:
                    state = active.pop(key, None)
                    if state is None:
                        continue
                    state['terminated'] = True
                    state['end_record'] = message['end_record']
                    if private:
                        raw = b''.join(state.pop('_parts'))
                        state['assembled_hex'] = raw.hex()
                        try:
                            state['json'] = json.loads(raw.decode('utf-8'))
                            state['json_valid'] = True
                        except (ValueError, UnicodeError):
                            state['json_valid'] = False
                    else:
                        # The public report intentionally never assembles or
                        # emits source JSON or configuration bytes.
                        state.pop('_parts')
                        state['json_valid'] = None
                    transfers.append(state)
                    if direction == 'host_to_device':
                        awaiting_ack[handle] = state
    for state in active.values():
        state.pop('_parts', None)
        state['warnings'].append('missing 0x0100 terminator')
        state['json_valid'] = None
        transfers.append(state)
    return transfers

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=pathlib.Path)
    p.add_argument('--out',type=pathlib.Path,help='JSON report path')
    p.add_argument('--handle',type=lambda s:int(s,0),help='HCI connection handle (hex supported)')
    p.add_argument('--name',default='Withings',help='Advertisement name filter (discovery only)')
    p.add_argument('--private',action='store_true',help='UNREDACTED: sensitive raw bytes, names, MACs, and credentials')
    p.add_argument('--all-handles',action='store_true',help='Include all ATT events')
    args=p.parse_args()
    stats=collections.Counter();adv=[];connections={};frags={};streams={};att_rows=[]
    handles=collections.Counter();wpp_handles=collections.Counter();warnings=[]
    for idx,ts,t,payload in records(args.capture):
        stats[f'record_type_{t:02x}']+=1
        if t==1 and len(payload)>=2:
            if payload[0]==0x05 and len(payload)>=5: # HCI disconnection complete
                h=int.from_bytes(payload[3:5],'little')
                for key in list(streams):
                    if key[0]==h:
                        if streams[key].pending(): warnings.append({'record':idx,'handle':f'0x{h:04X}','warning':'pending WPP bytes at disconnect','count':streams[key].pending()})
                        del streams[key]
                for key in list(frags):
                    if key[0]==h: del frags[key]
            if payload[0]==0x3E and len(payload)>3:
                sub=payload[2];data=payload[3:]
                if sub==0x02 and data:
                    count=data[0];pos=1
                    for _ in range(count):
                        if pos+9>len(data):break
                        evt=data[pos];addr=mac(data[pos+2:pos+8]);n=data[pos+8];pos+=9
                        if pos+n+1>len(data):break
                        fields=ad_fields(data[pos:pos+n]);pos+=n+1
                        names=[v.decode('utf-8','replace') for k,v in fields if k in (8,9)]
                        if any(args.name.lower() in name.lower() for name in names):
                            adv.append({'record':idx,'time':ts,'name':names[0] if args.private else '<redacted>',
                                        'mac':addr if args.private else '<redacted>','event_type':evt,
                                        'ad_types':[f'0x{k:02X}' for k,_ in fields]})
                if sub in (0x01,0x0A) and len(data)>=11:
                    h=int.from_bytes(data[1:3],'little')
                    connections[h]={'record':idx,'mac':mac(data[5:11]) if args.private else '<redacted>','role':data[3]}
            continue
        if t not in (2,3) or len(payload)<8:continue
        header=int.from_bytes(payload[:2],'little');h=header&0x0fff;pb=(header>>12)&3
        if args.handle is not None and h!=args.handle:continue
        n=int.from_bytes(payload[2:4],'little')
        if len(payload)<4+n:
            warnings.append({'record':idx,'warning':'truncated ACL packet'});continue
        piece=payload[4:4+n];direction='host_to_device' if t==2 else 'device_to_host'
        key=(h,direction)
        if pb in (0,2):
            if len(piece)<4:continue
            if key in frags: warnings.append({'record':idx,'handle':f'0x{h:04X}','warning':'overwritten incomplete L2CAP fragment'})
            l2len=int.from_bytes(piece[:2],'little');cid=int.from_bytes(piece[2:4],'little')
            frags[key]=[cid,l2len,bytearray(piece[4:])]
        elif pb==1 and key in frags: frags[key][2].extend(piece)
        else:continue
        cid,needed,buf=frags[key]
        if len(buf)<needed:continue
        del frags[key]
        if len(buf)>needed:
            warnings.append({'record':idx,'handle':f'0x{h:04X}','warning':'L2CAP payload overrun'});continue
        if cid!=4 or not buf:continue
        handles[h]+=1;op=buf[0]
        entry={'record':idx,'time':ts,'handle':f'0x{h:04X}','direction':direction,
               'att_opcode':f'0x{op:02X}','att_meaning':ATT.get(op,'unknown')}
        if op in (0x12,0x52,0x1B,0x1D) and len(buf)>=3:
            attr=int.from_bytes(buf[1:3],'little')
            entry['attribute_handle']=f'0x{attr:04X}'
            val=bytes(buf[3:]);entry['value_length']=len(val)
            if args.private:entry['att_value_hex']=val.hex()
            stream=streams.setdefault((h,direction,attr),WPPStream(args.private))
            # Don't interpret unrelated ATT attributes as WPP.
            if stream.pending() or (len(val)>=5 and val[0]==1):
                decoded=stream.feed(val,idx)
                if decoded:
                    entry['wpp_messages']=[m for m in decoded if 'command' in m]
                    entry['wpp_warnings']=[m for m in decoded if 'warning' in m]
                    wpp_handles[h]+=len(entry['wpp_messages'])
        att_rows.append(entry)
    for (h,d,attr),stream in streams.items():
        if stream.pending(): warnings.append({'handle':f'0x{h:04X}','direction':d,
                'attribute_handle':f'0x{attr:04X}','warning':'incomplete WPP stream at end of capture',
                'pending_bytes':stream.pending()})
    selected={args.handle} if args.handle is not None else (set(handles) if args.all_handles else set(wpp_handles))
    events=[e for e in att_rows if int(e['handle'],16) in selected and
            (args.private or args.all_handles or e.get('wpp_messages') or e.get('wpp_warnings') or
             e['att_opcode'] in ('0x02','0x03','0x13','0x01'))]
    configuration_transfers = reconstruct_configuration_transfers(events, private=args.private)
    report={'format':'Apple PacketLogger .pklg',
        'privacy':'PRIVATE: contains sensitive captured bytes' if args.private else 'PUBLIC: identifiers and payload bytes redacted',
        'capture':args.capture.name if args.private else '<redacted>',
        'record_counts':dict(stats),'advertisements':adv,
        'connections':{f'0x{h:04X}':v for h,v in connections.items() if h in selected},
        'att_counts_by_handle':{f'0x{k:04X}':v for k,v in handles.items()},
        'wpp_counts_by_handle':{f'0x{k:04X}':v for k,v in wpp_handles.items()},
        'timeline':events,'configuration_transfers':configuration_transfers,'warnings':warnings,
        'limitations':['Application-level WPP reassembly assumes continuation bytes on the same ATT attribute, direction, and connection.','Some devices may use different fragmentation conventions.','Raw PacketLogger files may include encrypted radio payloads not available to this parser.','Public mode hides payload bytes, names and MACs but timing and traffic metadata remain.']}
    out=args.out or args.capture.with_suffix('.withings.private.json' if args.private else '.withings.json')
    if args.private:
        print('WARNING: private output contains sensitive BLE data and credentials.')
    flags=os.O_WRONLY|os.O_CREAT|os.O_TRUNC
    fd=os.open(out,flags,0o600)
    with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    os.chmod(out,0o600)
    print(f'Analyzed {sum(stats.values())} PacketLogger records')
    print('WPP candidate handles:',{hex(k):v for k,v in wpp_handles.items()})
    print('Advertisements matched:',len(adv))
    print('Timeline events:',len(events))
    print('Warnings:',len(warnings))
    print('Logical 0x010D configuration transfers:',len(configuration_transfers))
    for t in configuration_transfers:
        print(f"  {t['handle']} {t['direction']} records {t['start_record']}-{t['end_record']}: {t['chunks']} chunks, {t['assembled_length']} bytes, terminated={t['terminated']}, acknowledged={t['acknowledged']}")
    print('Report:',out)
    for e in events:
        for w in e.get('wpp_messages',[]):
            print(f"{e['handle']} {e['direction']:15} {w['command']} {w['meaning']}")

if __name__=='__main__':main()
