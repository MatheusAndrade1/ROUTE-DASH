from xml.dom import minidom
import json
import os
import pathlib
from pathlib import Path
import re # replace function library

import time
from datetime import datetime

# gets the current path
currentPath = str(pathlib.Path(__file__).parent.resolve()) + "\\metadata\\"

if not os.path.exists(currentPath):
    os.makedirs(currentPath)

# defines the variables for the MPD parser
infoDict = {}
codecsList = []
idList = []
contentList = []
resolutionList = []
bandwidthList = []
publishTimeList = []

def parseMPD(strXML):
    # Parses the XML 
    dom = minidom.parseString(strXML).documentElement
    publishTimeList.append(dom.attributes['timeShiftBufferDepth'].value)

    elements = dom.getElementsByTagName('AdaptationSet')
    for element in elements:
        tempDict = {}
        for subelement in dom.getElementsByTagName('Representation'):
            try:
                res = subelement.attributes['width'].value + "x" + subelement.attributes['height'].value
            except:
                res = ""
            try:
                if element.attributes['contentType'].value == "video" and res != "":
                    tempDict.update({subelement.attributes['id'].value: [subelement.attributes['codecs'].value, subelement.attributes['bandwidth'].value, res]})
                if element.attributes['contentType'].value == "audio" and res == "":
                    tempDict.update({subelement.attributes['id'].value: [subelement.attributes['codecs'].value, subelement.attributes['bandwidth'].value]})
            except:
                if element.attributes['entType'].value == "video" and res != "":
                    tempDict.update({subelement.attributes['id'].value: [subelement.attributes['codecs'].value, subelement.attributes['bandwidth'].value, res]})
                if element.attributes['entType'].value == "audio" and res == "":
                    tempDict.update({subelement.attributes['id'].value: [subelement.attributes['codecs'].value, subelement.attributes['bandwidth'].value]})
        try:
            infoDict.update({element.attributes['contentType'].value: tempDict})
        except:
            infoDict.update({element.attributes['entType'].value: tempDict})

    # Writes the MPD file
    MPD = open("metadata\\manifest.MPD", "w")
    MPD.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + strXML)
    MPD.close()
    return infoDict

# defines the variables for the TSID parser

tsiList = []
bandwidthList = []
contentTypeList = []
extensionList = []
nameList = []

def parseTSID(strXML, path):
    # Parses the XML and the elements of interest from the TSID object
    dom = minidom.parseString(strXML).documentElement

    elements = dom.getElementsByTagName('LS')
    for element in elements:
        tsiList.append(element.attributes['tsi'].value)

    elements = dom.getElementsByTagName('FDT-Instance')
    for element in elements:
        bandwidthList.append(element.attributes['afdt:maxTransportSize'].value)

    elements = dom.getElementsByTagName('MediaInfo')
    for element in elements:
        contentTypeList.append(element.attributes['contentType'].value)
    
    elements = dom.getElementsByTagName('fdt:File')
    for element in elements:
        temp = element.attributes['Content-Location'].value.split(".")
        extensionList.append(temp[len(temp) - 1])
        nameList.append('-'.join(temp[0].split("-")[:-1]))

MPD_content = ""
temp_MPD_content = ""
numberOfMPDS = 0
TSID_complete = 0

# Gets the MPD part of the file
with open("metadata\\description_0") as f:
    found_MPD_content = False
    for line in f:
        pattern = re.compile('xml version="1.0" encoding="utf-8"', re.IGNORECASE)
        line = str(pattern.sub("", line))
        line = line.replace("<??>","")
    
        try:
            if line.find("<MPD") != -1:
                found_MPD_content = True

            if found_MPD_content:
                # Checks if the MPD has finished
                if line.find("</MPD>") != -1:
                    MPD_content = MPD_content + temp_MPD_content + line
                    infoDict = parseMPD(temp_MPD_content + line)
                    break
                # If it finds this line, it means the MPD is broken
                elif line.startswith("Content-Location"):
                    temp_MPD_content = ""
                    found_MPD_content = False
                else:
                    temp_MPD_content = temp_MPD_content + line
        except:
            pass
        try:
            if line.find("<S-TSID") != -1 and TSID_complete == 0:
                parseTSID(line, currentPath)
                TSID_complete = 1
        except:
            pass

# Organizes the dictionary to show on the terminal
keys = list(infoDict.keys())
treeDict = {}
for i in range(0,len(keys)): 
    treeDict.update({"AdaptationSet" + str(i):infoDict[keys[i]]})

treeDict = {"Period":treeDict}
treeDict = {"MPD":treeDict}

tree_str = json.dumps(treeDict, indent=4)
tree_str = tree_str.replace("\n    ", "\n")
tree_str = tree_str.replace('"', "")
tree_str = tree_str.replace('[', "")
tree_str = tree_str.replace(']', "")
tree_str = tree_str.replace(',', "")
tree_str = tree_str.replace("{", "")
tree_str = tree_str.replace("}", "")
tree_str = tree_str.replace("    ", "- ")
tree_str = tree_str.replace("  ", " ")

print(tree_str)

now = datetime.fromtimestamp(time.time())
lastRenamedFile = datetime.fromtimestamp(time.time())

if len(tsiList) != 0:
    while divmod(abs(lastRenamedFile - now), 60)[0] <= 5:
        # routine that changes the names of the 
        for file in os.listdir(currentPath):
            for i in range(0, len(tsiList)):
                now = datetime.fromtimestamp(time.time())
                # checks if the file name has the corresponding tsi value and if the file has any data
                if tsiList[i] in file and "description" in file and os.path.getsize(file) > 0:
                    newname = file

                    lastRenamedFile = datetime.fromtimestamp(time.time())

                    newname = newname.replace("description_" + tsiList[i], nameList[i])
                    newname = newname.replace("_", "-")
                    # Identifies the init file
                    if newname[-2:] == "-1":
                        newname = newname[:-2] + "-init"
                    
                    # Adds the extension
                    newname = newname + "." + extensionList[0] + contentTypeList[i][0]

                    newPath = currentPath + newname
                    # if the file already exists, it will merge the new and the old one
                    if Path(newPath).is_file():
                        #try:
                        data1 = ""
                        data2 = ""
                        with open(currentPath + file, 'r+', encoding="utf8", errors='ignore') as fp:
                            data1 = fp.read()
                            fp.truncate()
                        
                        with open(currentPath + file, 'w', encoding="utf8", errors='ignore') as fp:
                            fp.write("")
                        
                        with open(newPath, 'r', encoding="utf8", errors='ignore') as fp:
                            data2 = fp.read()
                        
                        with open (newPath, 'w', encoding="utf8") as fp:
                            fp.write(data2 + data1)

                    else:
                        try:
                            os.rename(currentPath + file, currentPath + newname)
                        except:
                            pass