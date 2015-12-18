#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains classes and functions to convert Ryu messages to ODL XMLs
and send them to an ODL controller. Currently needs a cleanup.

@author: Karel van de Plassche
@licence: GPLv3
"""
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser

from xml.dom.minidom import parseString

import dicttoxml

import shutil
import os
import logging

logger = logging.getLogger(__name__)
class OpenDaylight: 
    def __init__(self, ip, node="openflow:55930", port="8181", xml_path=""):
        self.ip = ip
        self.node = node
        self.port = port
        # All flows in ODL should have a unique ID, so we need to track IDs used. 
        # This is the simpelest way to do this
        self.highest_unused_id = 0
        shutil.rmtree("./ODL", ignore_errors = True)
        os.mkdir("./ODL")
        self.msgs = []
        
    def convert_action(self, action):
        action_dict = {}
        if action.__class__ == parser.OFPActionOutput:
            action_dict["output-action"] = {"max-length": action.max_len, 
                                            "output-node-connector": action.port}  
        elif action.__class__ == parser.OFPActionGroup:
            action_dict["group-action"] = {"group-id": action.group_id}
        elif action.__class__ == parser.OFPActionSetField:
            setfield_dict = action_dict["set-field"] = {}
            if action.key == "vlan_vid":
                setfield_dict["vlan-match"] = {}
                if action.value.__class__ == tuple:
                    id_ = action.value[0] & action.value[1]
                else:
                    id_ = action.value
                setfield_dict["vlan-match"]["vlan-id"] = {"vlan-id": 0x0FFF & id_}
                if (id_ & 0xF000 == 0x1000):
                    setfield_dict["vlan-match"]["vlan-id"]["vlan-id-present"] = True
                elif (id_ & 0xF000 == 0x0000):
                    setfield_dict["vlan-match"]["vlan-id"]["vlan-id-present"] = False
                else:
                    logger.exception("Invalid VLAN Id")
            else:
                raise Exception("Unknown field")
        elif action.__class__ == parser.OFPActionPopVlan:
            action_dict = {"pop-vlan-action": {}}
        
        else:
            raise Exception("Unknown action")
        return action_dict
            
    def convert_msg(self, msg):
        logger.debug("received message \n" + str(msg))
        if msg.__class__ == parser.OFPFlowMod:
            #json_dict = {"flow": {}}
            flow_dict = {}
            flow_dict["idle-timeout"] = msg.idle_timeout
            flow_dict["cookie_mask"] = msg.cookie_mask
            flow_dict["id"] = self.highest_unused_id
            self.highest_unused_id +=1
            flow_dict["priority"] = msg.priority
            flow_dict["table_id"] = msg.table_id
            flow_dict["hard-timeout"] = msg.hard_timeout
            
            flow_dict["instructions"] = {}
            
            ###################################################################
            # Instructions                                                    #
            ###################################################################
            instruct_list = flow_dict["instructions"] = []
            logger.debug("decoding instructions\n" + str(msg.instructions))
            for i, instruction in enumerate(msg.instructions):
                logger.debug("instruction " + str(i) + "\n" + str(instruction))
                instruct_dict = {"order": i}
                if instruction.__class__ == parser.OFPInstructionGotoTable:
                    instruct_dict["go-to-table"] = {}
                    instruct_dict["go-to-table"]["table_id"] = instruction.table_id
                    
                elif instruction.__class__ == parser.OFPInstructionActions:
                    logger.debug("decoding actions\n" + str(instruction.actions))
                    for action in instruction.actions:
                        logger.debug("action\n" + str(action))
                        action_dict = self.convert_action(action)
                            
                    if instruction.type == ofproto.OFPIT_WRITE_ACTIONS:                    
                        instruct_dict["write-actions"] = {}
                        instruct_dict["write-actions"]["action"] = {"order": 0}
                        instruct_dict["write-actions"]["action"].update(action_dict)
                    elif instruction.type == ofproto.OFPIT_APPLY_ACTIONS:
                        instruct_dict["apply-actions"] = {}
                        instruct_dict["apply-actions"]["action"] = {"order": 0}
                        instruct_dict["apply-actions"]["action"].update(action_dict)
                    else:
                        raise Exception("Not implemented yet")
                    

                    #else:
                    #    raise Exception("Unknown instruction actions")
                else:                  
                    raise Exception("Unknown instruction")
                instruct_list.append({"instruction": instruct_dict})
            
            ###################################################################
            # Matches                                                         #
            ###################################################################
            match_dict = flow_dict["match"]  = {}
            logger.debug("decoding matches\n" + str(msg.match))
            if msg.match.__class__ == parser.OFPMatch:
                for match in msg.match.iteritems():
                    logger.debug("match\n" + str(match))
                    if match[0] == "in_port":
                        match_dict["in-port"] = match[1]
                    elif match[0] == "vlan_vid":
                        match_dict["vlan-match"] = {}
                        if match[1].__class__ == tuple:
                            id_ = match[1][0] & match[1][1]
                        else:
                            id_ = match[1]
                        match_dict["vlan-match"]["vlan-id"] = {"vlan-id": 0x0FFF & id_}
                        if (id_ & 0xF000 == 0x1000):
                            match_dict["vlan-match"]["vlan-id"]["vlan-id-present"] = True
                        elif (id_ & 0xF000 == 0x0000):
                            match_dict["vlan-match"]["vlan-id"]["vlan-id-present"] = False
                        else:
                            logger.exception("Invalid VLAN Id")
                    elif match[0] == "eth_dst":
                        match_dict["ethernet-match"] = {}
                        match_dict["ethernet-match"]["ethernet-destination"] = {"address": match[1]}
                    else:
                        raise Exception("Unknown match field")
            else:
                raise Exception("Unknown match")
            json_dict = {"flow": flow_dict}
            
        elif msg.__class__ == parser.OFPGroupMod:
            json_dict = {"group": {}}
            json_dict["group"] = {"group-id": msg.group_id,
                                  "group-type": OpenDaylight.ryu_grouptype_to_ODL(msg.type),
                                  "buckets": []}
            ###################################################################
            # Buckets                                                         #
            ###################################################################
            logger.debug("decoding buckets\n" + str(msg.buckets))
            for i, bucket in enumerate(msg.buckets):
                logger.debug("bucket " + str(i) + "\n" + str(bucket))
                if bucket.__class__ == parser.OFPBucket:
                    # This is a bit hackish as Python doesn't support dicts
                    # with duplicate keys
                    bucket_dict = {"bucket-id": i,
                                   "watch_group": bucket.watch_group,
                                   "watch_port": bucket.watch_port}
                    bucket_list = [bucket_dict]
                    for j, bucket_action in enumerate(bucket.actions):
                        logger.debug("bucket action" + str(j) + "\n" + str(bucket_action))
                        bucket_action_dict = self.convert_action(bucket_action)
                        bucket_action_dict["order"] = j
                       
                        bucket_list.append({"action": bucket_action_dict})
                else:
                    raise Exception("Unknown bucket")
                json_dict["group"]["buckets"].append({"bucket": bucket_list})
        else:
            raise Exception("Unknown msg")
        
        logger.debug("created json dictionary \n" + str(json_dict))
        
        return json_dict
        
    @classmethod
    def ryu_grouptype_to_ODL(cls, id_):
        if id_ == 0:
            return "group-all"
        if id_ == 2:
            return "group-indirect"
        else:
            raise Exception("Unknown group type")
            
    @classmethod  
    def oxm_to_ODL(k, uv):
        """Copied from ryu/ofproto/oxm_fields.py._to_jsondict(k, uv)"""
        if isinstance(uv, tuple):
            (value, mask) = uv
        else:
            value = uv
            mask = None
        return {"OXMTlv": {"field": k, "value": value, "mask": mask}}
        
    def write_to_file(self):
        with open("./ODL/send.py", 'w') as script:
            script.write("#!/usr/bin/env python\n")
            script.write("import requests\n")
            script.write("import json\n\n")

            script.write("controller_ip = \"" + self.ip + "\"\n")
            script.write("controller_port = \"" + self.port + "\"\n")
            script.write("node = \"" + self.node + "\"\n")
            script.write("restconf_url = \"http://\" + controller_ip + \":\" + controller_port + \"/restconf\"\n")
            script.write("node_url = restconf_url + \"/config/opendaylight-inventory:nodes/node/\" + node\n")

            script.write("urls = [\n")   
        for i, msg in enumerate(self.msgs):
            with open("./ODL/" + str(i) + ".xml", 'w') as outfile:
                #json.dump(entry , outfile, indent=4)
                entry = self.convert_msg(msg)
                xml = dicttoxml.dicttoxml(entry, attr_type=False, root=False)
                if xml.startswith("<flow>"):
                    _, xml = xml.split("<flow>",1)
                    xml = "<flow xmlns=\"urn:opendaylight:flow:inventory\">" + xml
                elif  xml.startswith("<group>"):
                    _, xml = xml.split("<group>",1)
                    xml = "<group xmlns=\"urn:opendaylight:flow:inventory\">" + xml
                xml = xml.replace("<item>","")
                xml = xml.replace("</item>","")
                dom = parseString(xml)
                outfile.write(dom.toprettyxml())
            with open("./ODL/send.py", 'a') as script:
                if "flow" in entry:
                    script.write("        node_url + \"/table/" + 
                                 str(entry["flow"]["table_id"]) + 
                                 "/flow/" +
                                 str(entry["flow"]["id"]) +
                                 "\",\n")
                elif "group" in entry:
                    script.write("        node_url + \"/group/" +
                                 str(entry["group"]["group-id"]) +
                                 "\",\n")
                
        with open("./ODL/send.py", 'a') as script:
            script.write("        ]\n")
            script.write("for i,url in enumerate(urls):\n")
            script.write("    data=open(str(i) + \".xml\").read()\n")
            script.write("    r = requests.put(url, data,\n")
            script.write("                     auth=('admin', 'admin'),\n")
            script.write("                     headers={'Accept':'application/xml',\n")
            script.write("                     'Content-Type':'application/xml'})\n")
            script.write("    if r.status_code != 200:\n")
            script.write("        print 'SENDING FAILED'\n")
            script.write("        print r.url\n")
            script.write("        print r.text\n")