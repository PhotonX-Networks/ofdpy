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
import copy
import sys

logger = logging.getLogger(__name__)


def convert_vlan(id_):
    vlan_dict = {"vlan-id": 0x0FFF & id_}
    if (id_ & 0x0FFF != 0x0000):
        vlan_dict["vlan-id-present"] = True
    elif (id_ & 0x0FFF == 0x0000):
        vlan_dict["vlan-id-present"] = False
    else:
        logger.exception("Invalid VLAN Id")
    return vlan_dict

def convert_action(action):
    logger.debug("decoding action\n" + str(action))
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
            vlan_dict = convert_vlan(id_)
            setfield_dict["vlan-match"]["vlan-id"] = vlan_dict
        else:
            raise Exception("Unknown field")
    elif action.__class__ == parser.OFPActionPopVlan:
        action_dict = {"pop-vlan-action": {}}

    else:
        raise Exception("Unknown action")
    logger.debug("decoded action\n" + str(action_dict) + "\n")
    return action_dict


def convert_matchs(matchs):
    matchs_list = []
    logger.debug("decoding matchs\n" + str(matchs.__dict__) + "\n")
    for i, match in enumerate(matchs.iteritems()):
        match_dict = convert_match(match)
        matchs_keys = [match.keys() for match in matchs_list]
        try:
            index = matchs_keys.index(match_dict.keys())
        except ValueError:
            matchs_list.append(match_dict)
        else:
            matchs_list[index][match_dict.keys()[0]][match_dict[match_dict.keys()[0]].keys()[0]] = match_dict[match_dict.keys()[0]][match_dict[match_dict.keys(    )[0]].keys()[0]]
    logger.debug("decoded matchs\n" + str(matchs_list) + "\n")
    return matchs_list

def convert_match(match):
    logger.debug("decoding match\n" + str(match))
    match_dict = {}
    if match[0] == "in_port":
        match_dict["in-port"] = match[1]

    elif match[0] == "vlan_vid":
        match_dict["vlan-match"] = {}
        if match[1].__class__ == tuple:
            id_ = match[1][0] & match[1][1]
        else:
            id_ = match[1]
        vlan_dict = convert_vlan(id_)
        match_dict["vlan-match"]["vlan-id"] = vlan_dict

    elif match[0] == "eth_dst":
        if match[1].__class__ == tuple:
            eth = match[1][0]
            eth_mask = match[1][1]
        else:
            eth = match[1]
            eth_mask = 'ff:ff:ff:ff:ff:ff'

        match_dict["ethernet-match"] = {}
        match_dict["ethernet-match"]["ethernet-destination"] = {"address":
                                                                eth,
                                                                "mask":
                                                                eth_mask}
    elif match[0] == "eth_src":
        if match[1].__class__ == tuple:
            eth = match[1][0]
            eth_mask = match[1][1]
        else:
            eth = match[1]
            eth_mask = 'ff:ff:ff:ff:ff:ff'

        match_dict["ethernet-match"] = {}
        match_dict["ethernet-match"]["ethernet-source"] = {"address":
                                                                eth,
                                                                "mask":
                                                                eth_mask}


    elif match[0] == "eth_type":
        match_dict["ethernet-match"] = {}
        match_dict["ethernet-match"]["ethernet-type"] = {"type":
                                                         match[1]}
    elif match[0] == "ip_dscp":
        match_dict["ip-match"] = {}
        match_dict["ip-match"] = {"ip-dscp":
                                                         match[1]}
    else:
        raise Exception("Unknown match field")
    logger.debug("decoded match\n" + str(match_dict) + "\n")
    return match_dict


def convert_instructions(instructions):
    instruction_list = []
    logger.debug("decoding instructions\n" + str(instructions) + "\n")
    for i, instruction in enumerate(instructions):
        instruction_dict = convert_instruction(instruction)
        instruction_dict["instruction"]["order"] = i
        instruction_list.append(instruction_dict)
    logger.debug("decoded instructions\n" + str(instruction_dict) + "\n")
    return instruction_list


def convert_instruction(instruction):
    logger.debug("decoding instruction\n" + str(instruction))
    instruction_dict = {}
    if instruction.__class__ == parser.OFPInstructionGotoTable:
            instruction_dict["go-to-table"] = {}
            instruction_dict["go-to-table"]["table_id"] = instruction.table_id

    elif instruction.__class__ == parser.OFPInstructionActions:
        for action in instruction.actions:
            action_dict = convert_action(action)

        if instruction.type == ofproto.OFPIT_WRITE_ACTIONS:
            instruction_dict["write-actions"] = {}
            instruction_dict["write-actions"]["action"] = {"order": 0}
            instruction_dict["write-actions"]["action"].update(action_dict)

        elif instruction.type == ofproto.OFPIT_APPLY_ACTIONS:
            instruction_dict["apply-actions"] = {}
            instruction_dict["apply-actions"]["action"] = {"order": 0}
            instruction_dict["apply-actions"]["action"].update(action_dict)

        else:
            raise Exception("Not implemented yet")
    else:
        raise Exception("Unknown instruction")
    result = {"instruction": instruction_dict}
    logger.debug("decoded instruction\n" + str(result) + "\n")
    return result


def convert_buckets(buckets):
    logger.debug("decoding buckets\n" + str(buckets) + "\n")
    buckets_list = []
    for i, bucket in enumerate(buckets):
        logger.debug("decoding bucket " + str(i) + "\n" + str(bucket) + "\n")
        if bucket.__class__ == parser.OFPBucket:
            # This is a bit hackish as Python doesn't support dicts
            # with duplicate keys
            bucket_dict = {"bucket-id": i,
                           "watch_group": bucket.watch_group,
                           "watch_port": bucket.watch_port}
            bucket_list = [bucket_dict]
            for j, bucket_action in enumerate(bucket.actions):

                bucket_action_dict = convert_action(bucket_action)
                bucket_action_dict["order"] = j
                bucket_list.append({"action": bucket_action_dict})
            logger.debug("decoded bucket\n" + str(bucket_list) + "\n")
        else:
            raise Exception("Unknown bucket")
        buckets_list.append({"bucket": bucket_list})
        logger.debug("decoded buckets\n" + str(buckets_list) + "\n")
    return buckets_list


class OpenDaylight:
    folder = sys.argv[0].split('.')[0]
    def __init__(self, ip, node="openflow:55930", port="8181", xml_path="", flow_start=None):
        self.ip = ip
        self.node = node
        self.port = port
        # All flows in ODL should have a unique ID, so we need to track IDs
        # used. This is the simpelest way to do this
	if not flow_start:
            flow_start = 0
        self.highest_unused_id = flow_start
        shutil.rmtree(os.path.join('.', self.folder), ignore_errors=True)
        os.mkdir(os.path.join('.', self.folder))
        self.msgs = []

    def convert_msg(self, msg):
        logger.info("received message \n" + str(msg) + "\n")
        if msg.__class__ == parser.OFPFlowMod:
            flow_dict = {"idle-timeout":  msg.idle_timeout,
                         "cookie_mask":   msg.cookie_mask,
                         "id":            self.highest_unused_id,
                         "priority":      msg.priority,
                         "table_id":      msg.table_id,
                         "hard-timeout":  msg.hard_timeout}
            flow_dict = {k: v for k, v in flow_dict.iteritems() if v is not None}

            self.highest_unused_id += 1

            flow_dict["instructions"] = convert_instructions(msg.instructions)

            flow_dict["match"] = convert_matchs(msg.match)
            json_dict = {"flow": flow_dict}

        elif msg.__class__ == parser.OFPGroupMod:
            group_dict = {"group-id":    msg.group_id,
                          "group-type":  OpenDaylight.ryu_grouptype_to_ODL(msg.type),
                          "buckets":     []}
            ###################################################################
            # Buckets                                                         #
            ###################################################################
            group_dict["buckets"] = convert_buckets(msg.buckets)
            json_dict = {"group": group_dict}
        else:
            raise Exception("Unknown msg")
        
        logger.info("created json dictionary \n" + str(json_dict) + "\n")
        
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
        lines = [
            "#!/usr/bin/env python\n",
            "import sys\n",
            "import requests\n",
            "import json\n\n",

            "controller_ip = \"" + self.ip + "\"\n",
            "controller_port = \"" + self.port + "\"\n",
            "node = \"" + self.node + "\"\n",
            "restconf_url = \"http://\" + controller_ip + \":\" + controller_port + \"/restconf\"\n",
            "node_url = restconf_url + \"/config/opendaylight-inventory:nodes/node/\" + node\n",

            "urls = [\n"]

        urlstr = []
        for i, msg in enumerate(self.msgs):
            with open(os.path.join('.', self.folder, str(i) + ".xml"), 'w') as outfile:
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

            if "flow" in entry:
                urlstr.append("node_url + \"/table/" + 
                             str(entry["flow"]["table_id"]) +
                             "/flow/" +
                             str(entry["flow"]["id"]) +
                             "\"")
            elif "group" in entry:
                urlstr.append("node_url + \"/group/" +
                             str(entry["group"]["group-id"]) +
                             "\"")

        for url in urlstr:
            lines.extend("        " + url + ",\n")

        lines.extend(["        ]\n",
                      "if len(sys.argv) > 1:\n",
                      "    dolist = [int(x) for x in sys.argv[1].split(',')]\n",
                      "else:\n",
                      "    dolist = [i for i, __ in enumerate(urls)]\n\n"])

        with open(os.path.join('.', self.folder, "send.py"), 'a') as script:
            bottom = [    
                          "for i,url in enumerate(urls):\n",
                          "    if i in dolist:\n",
                          "        data=open(str(i) + \".xml\").read()\n",
                          "        r = requests.put(url, data,\n",
                          "                         auth=('admin', 'admin'),\n",
                          "                         headers={'Accept':'application/xml',\n",
                          "                         'Content-Type':'application/xml'})\n",
                          "        if r.status_code != 200:\n",
                          "            print 'SENDING FAILED'\n",
                          "            print r.url\n",
                          "            print r.text\n"]
            for line in (lines + bottom):
                script.write(line)


        with open(os.path.join('.', self.folder, "remove.py"), 'w') as script:
            bottom = ["urls.reverse()\n",
                      "for i,url in enumerate(urls):\n",
                      "    if i in dolist:\n",
                      "        r = requests.delete(url,\n",
                      "                            auth=('admin', 'admin'),\n",
                      "                            headers={'Accept':'application/xml',\n",
                      "                            'Content-Type':'application/xml'})\n",
                      "        if r.status_code != 200:\n",
                      "            print 'SENDING FAILED'\n",
                      "            print r.url\n",
                      "            print r.text\n"]
            for line in (lines + bottom):
                script.write(line)
