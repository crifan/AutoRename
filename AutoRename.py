# Function: IDA script plugin, auto rename for all (Functions, Names) symbols
# Author: Crifan Li
# Update: 20240101

import re
import os
import json

import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
# import time
import codecs
import copy

import idc
import idaapi
import idautils
import ida_nalt
import ida_segment

################################################################################
# Document
################################################################################

# IDA Python API:
#   https://www.hex-rays.com/products/ida/support/idapython_docs/index.html
#
#   idc
#     https://hex-rays.com//products/ida/support/idapython_docs/idc.html

################################################################################
# Config & Settings & Const
################################################################################

# verbose log
isVerbose = False
# isVerbose = True

# isFailForUnsupportInstruction = False
isFailForUnsupportInstruction = True

# export result to json file
# isExportResult = False
isExportResult = True

if isExportResult:
  outputFolder = None
  # outputFolder = "/Users/crifan/dev/dev_root/crifan/github/AutoRename/debug"

SINGLE_INSTRUCTION_SIZE = 4 # bytes
# for rename, the max number of instruction to support
# MAX_INSTRUCTION_NUM = 6
MAX_INSTRUCTION_NUM = 8
MAX_INSTRUCTION_SIZE = MAX_INSTRUCTION_NUM * SINGLE_INSTRUCTION_SIZE

IdaReservedStr = [
  "class",
  "id",
  "const",
  "char",
  "void",
  "return",
  "private",
  "namespace",
  "catch",
  "do",
  "while",
]

PrologueEpilogueRegList = [
  "X19",
  "X20",
  "X21",
  "X22",
  "X23",
  "X24",
  "X25",
  "X26",
  "X27",
  "X28",
  "X29",
  "X30",

  "D8",
  "D9",
]

ArmSpecialRegNameList = [
  "SB",
  "TR",
  "XR",
  "IP",
  "IP0",
  "IP1",
  "PR",
  "SP",
  "FP",
  "LR",
  "PC",
]

################################################################################
# Util Function
################################################################################

def logMain(mainStr):
  mainDelimiter = "="*40
  print("%s %s %s" % (mainDelimiter, mainStr, mainDelimiter))

def logSub(subStr):
  subDelimiter = "-"*30
  print("%s %s %s" % (subDelimiter, subStr, subDelimiter))

def logSubSub(subStr):
  subsubDelimiter = "-"*20
  print("%s %s %s" % (subsubDelimiter, subStr, subsubDelimiter))


def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
    """Convert datetime to string

    Args:
        inputDatetime (datetime): datetime value
    Returns:
        str
    Raises:
    Examples:
        datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
    """
    datetimeStr = inputDatetime.strftime(format=format)
    # print("inputDatetime=%s -> datetimeStr=%s" % (inputDatetime, datetimeStr)) # 2020-04-21 15:08:59.787623
    return datetimeStr

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string

    eg:
        20171111_220722

    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    # curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    curDatetimeStr = datetimeToStr(curDatetime, format=outputFormat)
    return curDatetimeStr

def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
    """
        save json dict into file
        for non-ascii string, output encoded string, without \\u xxxx
    """
    with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
        json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
        # logging.debug("Complete save json %s", fullFilename)

def isObjcFunctionName(funcName):
  """
  check is ObjC function name or not
  eg:
    "+[WAAvatarStringsActions editAvatar]" -> True
    "-[ParentGroupInfoViewController initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:]" -> True
    "-[OKEvolveSegmentationVC proCard]_116" -> True
    "-[WAAvatarStickerUpSellSupplementaryView .cxx_destruct]" -> True
    "sub_10004C6D8" -> False
    "protocol witness for RawRepresentable.init(rawValue:) in conformance UIFont.FontWeight" -> True
  """
  isMatchObjcFuncName = re.match("^[\-\+]\[\w+ [\w\.\:]+\]\w*$", funcName)
  isObjcFuncName = bool(isMatchObjcFuncName)
  # print("funcName=%s -> isObjcFuncName=%s" % (funcName, isObjcFuncName))
  return isObjcFuncName

################################################################################
# IDA Util Function
################################################################################

def ida_getInfo():
  """
  get IDA info
  """
  info = idaapi.get_inf_structure()
  # print("info=%s" % info)
  return info

def ida_printInfo(info):
  """
  print IDA info
  """
  version = info.version
  print("version=%s" % version)
  is64Bit = info.is_64bit()
  print("is64Bit=%s" % is64Bit)
  procName = info.procname
  print("procName=%s" % procName)
  entryPoint = info.start_ea
  print("entryPoint=0x%X" % entryPoint)
  baseAddr = info.baseaddr
  print("baseAddr=0x%X" % baseAddr)

def ida_printAllImports():
  """
  print all imports lib and functions inside lib"""
  nimps = ida_nalt.get_import_module_qty()
  print("Found %d import(s)..." % nimps)
  for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
      print("Failed to get import module name for [%d] %s" % (i, name))
      name = "<unnamed>"
    else:
      print("[%d] %s" % (i, name))

    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)

def ida_printSegment(curSeg):
  """
  print segment info
    Note: in IDA, segment == section
  """
  segName = curSeg.name
  # print("type(segName)=%s" % type(segName))
  segSelector = curSeg.sel
  segStartAddr = curSeg.start_ea
  segEndAddr = curSeg.end_ea
  print("Segment: [0x%X-0x%X] name=%s, selector=%s : seg=%s" % (segStartAddr, segEndAddr, segName, segSelector, curSeg))

def ida_getSegmentList():
  """
  get segment list
  """
  segList = []
  segNum = ida_segment.get_segm_qty()
  for segIdx in range(segNum):
    curSeg = ida_segment.getnseg(segIdx)
    # print("curSeg=%s" % curSeg)
    segList.append(curSeg)
    # ida_printSegment(curSeg)
  return segList

def ida_testGetSegment():
  """
  test get segment info
  """
  # textSeg = ida_segment.get_segm_by_name("__TEXT")
  # dataSeg = ida_segment.get_segm_by_name("__DATA")

  # ida_getSegmentList()

  # NAME___TEXT = "21"
  # NAME___TEXT = 21
  # NAME___TEXT = "__TEXT,__text"
  # NAME___TEXT = "__TEXT:__text"
  # NAME___TEXT = ".text"

  """
    __TEXT,__text
    __TEXT,__stubs
    __TEXT,__stub_helper
    __TEXT,__objc_stubs
    __TEXT,__const
    __TEXT,__objc_methname
    __TEXT,__cstring
    __TEXT,__swift5_typeref
    __TEXT,__swift5_protos
    __TEXT,__swift5_proto
    __TEXT,__swift5_types
    __TEXT,__objc_classname
    __TEXT,__objc_methtype
    __TEXT,__gcc_except_tab
    __TEXT,__ustring
    __TEXT,__unwind_info
    __TEXT,__eh_frame
    __TEXT,__oslogstring

    __DATA,__got
    __DATA,__la_symbol_ptr
    __DATA,__mod_init_func
    __DATA,__const
    __DATA,__cfstring
    __DATA,__objc_classlist
    __DATA,__objc_catlist
    __DATA,__objc_protolist
    __DATA,__objc_imageinfo
    __DATA,__objc_const
    __DATA,__objc_selrefs
    __DATA,__objc_protorefs
    __DATA,__objc_classrefs
    __DATA,__objc_superrefs
    __DATA,__objc_ivar
    __DATA,__objc_data
    __DATA,__data
    __DATA,__objc_stublist
    __DATA,__swift_hooks
    __DATA,__swift51_hooks
    __DATA,__s_async_hook
    __DATA,__swift56_hooks
    __DATA,__thread_vars
    __DATA,__thread_bss
    __DATA,__bss
    __DATA,__common
  """

  # __TEXT,__text
  NAME___text = "__text"
  textSeg = ida_segment.get_segm_by_name(NAME___text)
  print("textSeg: %s -> %s" % (NAME___text, textSeg))
  ida_printSegment(textSeg)

  # __TEXT,__objc_methname
  NAME___objc_methname = "__objc_methname"
  objcMethNameSeg = ida_segment.get_segm_by_name(NAME___objc_methname)
  print("objcMethNameSeg: %s -> %s" % (NAME___objc_methname, objcMethNameSeg))
  ida_printSegment(objcMethNameSeg)

  # __DATA,__got
  NAME___got = "__got"
  gotSeg = ida_segment.get_segm_by_name(NAME___got)
  print("gotSeg: %s -> %s" % (NAME___got, gotSeg))
  ida_printSegment(gotSeg)

  # __DATA,__data
  # NAME___DATA = "22"
  # NAME___DATA = 22
  NAME___DATA = "__data"
  dataSeg = ida_segment.get_segm_by_name(NAME___DATA)
  print("dataSeg: %s -> %s" % (NAME___DATA, dataSeg))
  ida_printSegment(dataSeg)

  # exist two one: __TEXT,__const / __DATA,__const
  NAME___const = "__const"
  constSeg = ida_segment.get_segm_by_name(NAME___const)
  print("constSeg: %s -> %s" % (NAME___const, constSeg))
  ida_printSegment(constSeg)

def ida_getDemangledName(origSymbolName):
  """
  use IDA to get demangled name for original symbol name
  """
  retName = origSymbolName
  # demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DN))
  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
  demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
  if demangledName:
    retName = demangledName

  # do extra post process:
  # remove/replace invalid char for non-objc function name
  isNotObjcFuncName = not isObjcFunctionName(retName)
  # print("isNotObjcFuncName=%s" % isNotObjcFuncName)
  if isNotObjcFuncName:
    retName = retName.replace("?", "")
    retName = retName.replace(" ", "_")
    retName = retName.replace("*", "_")
  # print("origSymbolName=%s -> retName=%s" % (origSymbolName, retName))
  return retName

def ida_getFunctionEndAddr(funcAddr):
  """
  get function end address
    Example:
      0x1023A2534 -> 0x1023A2540
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  return funcAddrEnd

def ida_getFunctionSize(funcAddr):
  """
  get function size
    Example:
      0x1023A2534 -> 12
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  funcAddStart = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_START)
  funcSize = funcAddrEnd - funcAddStart
  return funcSize

def ida_getFunctionName(funcAddr):
  """
  get function name
    Exmaple:
      0x1023A2534 -> "sub_1023A2534"
  """
  funcName = idc.get_func_name(funcAddr)
  return funcName

def ida_getDisasmStr(funcAddr):
  """
  get disasmemble string
    Exmaple:
      0x1023A2534 -> "MOV X5, X0"
  """
  # method 1: generate_disasm_line
  # disasmLine_forceCode = idc.generate_disasm_line(funcAddr, idc.GENDSM_FORCE_CODE)
  # print("disasmLine_forceCode: type=%s, val=%s" % (type(disasmLine_forceCode), disasmLine_forceCode))
  # disasmLine_multiLine = idc.generate_disasm_line(funcAddr, idc.GENDSM_MULTI_LINE)
  # print("disasmLine_multiLine: type=%s, val=%s" % (type(disasmLine_multiLine), disasmLine_multiLine))

  # method 2: GetDisasm
  disasmLine = idc.GetDisasm(funcAddr)
  # print("disasmLine: type=%s, val=%s" % (type(disasmLine), disasmLine))

  # post process
  # print("disasmLine=%s" % disasmLine)
  # "MOV             X4, X21" -> "MOV X4, X21"
  disasmLine = re.sub("\s+", " ", disasmLine)
  # print("disasmLine=%s" % disasmLine)
  return disasmLine

def ida_getFunctionAddrList():
  """
  get function address list
  """
  functionIterator = idautils.Functions()
  functionAddrList = []
  for curFuncAddr in functionIterator:
    functionAddrList.append(curFuncAddr)
  return functionAddrList

def ida_rename(curAddr, newName, retryName=None):
  """
  rename <curAddr> to <newName>. if fail, retry with with <retryName> if not None
    Example:
      0x3B4E28, "X2toX21_X1toX20_X0toX19_4E28", "X2toX21_X1toX20_X0toX19_3B4E28" -> True, "X2toX21_X1toX20_X0toX19_4E28"
  """
  # print("curAddr=0x%X, newName=%s, retryName=%s" % (curAddr, newName, retryName))
  isRenameOk = False
  renamedName = None

  isOk = idc.set_name(curAddr, newName)
  # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, newName))
  if isOk == 1:
    isRenameOk = True
    renamedName = newName
  else:
    if retryName:
      isOk = idc.set_name(curAddr, retryName)
      # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, retryName))
      if isOk == 1:
        isRenameOk = True
        renamedName = retryName

  # print("isRenameOk=%s, renamedName=%s" % (isRenameOk, renamedName))
  return (isRenameOk, renamedName)

def ida_getCurrentFolder():
  """
  get current folder for IDA current opened binary file
    Example:
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app/Frameworks/SharedModules.framework
  """
  curFolder = None
  inputFileFullPath = ida_nalt.get_input_file_path()
  # print("inputFileFullPath=%s" % inputFileFullPath)
  if inputFileFullPath.startswith("/var/containers/Bundle/Application"):
    # inputFileFullPath=/var/containers/Bundle/Application/2BE964D4-8DF0-4858-A06D-66CA8741ACDC/WhatsApp.app/WhatsApp
    # -> maybe IDA bug -> after debug settings, output iOS device path, but later no authority to write exported file to it
    # so need to avoid this case, change to output to PC side (Mac) current folder
    curFolder = "."
  else:
    curFolder = os.path.dirname(inputFileFullPath)
  # print("curFolder=%s" % curFolder)

  # debugInputPath = ida_nalt.dbg_get_input_path()
  # print("debugInputPath=%s" % debugInputPath)

  curFolder = os.path.abspath(curFolder)
  # print("curFolder=%s" % curFolder)
  # here work:
  # . -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
  return curFolder

def isDefaultSubFuncName(funcName):
  """
  check is default sub_XXX function or not from name
  eg:
    sub_F332C0 -> True, "F332C0"
  """
  isSub = False
  addressStr = None
  # subMatch = re.match("^sub_[0-9A-Za-z]+$", funcName)
  subMatch = re.match("^sub_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
  # print("subMatch=%s" % subMatch)
  if subMatch:
    isSub = True
    addressStr = subMatch.group("addressStr")
  return isSub, addressStr

def isReservedPrefix_loc(funcName):
  """
  check is reserved prefix loc_XXX name or not
  eg:
    loc_100007A2C -> True, "100007A2C"
  """
  isLoc = False
  addressStr = None
  locMatch = re.match("^loc_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
  # print("locMatch=%s" % locMatch)
  if locMatch:
    isLoc = True
    addressStr = locMatch.group("addressStr")
  return isLoc, addressStr

def isDefaultSubFunction(curAddr):
  """
  check is default sub_XXX function or not from address
  """
  isDefSubFunc = False
  curFuncName  = ida_getFunctionName(curAddr)
  # print("curFuncName=%s" % curFuncName)
  if curFuncName:
    isDefSubFunc, subAddStr = isDefaultSubFuncName(curFuncName)
  return isDefSubFunc, curFuncName

def ida_getCurrentFolder():
  """
  get current folder for IDA current opened binary file
    Example:
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app/Frameworks/SharedModules.framework
  """
  curFolder = None
  inputFileFullPath = ida_nalt.get_input_file_path()
  # print("inputFileFullPath=%s" % inputFileFullPath)
  if inputFileFullPath.startswith("/var/containers/Bundle/Application"):
    # inputFileFullPath=/var/containers/Bundle/Application/2BE964D4-8DF0-4858-A06D-66CA8741ACDC/WhatsApp.app/WhatsApp
    # -> maybe IDA bug -> after debug settings, output iOS device path, but later no authority to write exported file to it
    # so need to avoid this case, change to output to PC side (Mac) current folder
    curFolder = "."
  else:
    curFolder = os.path.dirname(inputFileFullPath)
  # print("curFolder=%s" % curFolder)

  # debugInputPath = ida_nalt.dbg_get_input_path()
  # print("debugInputPath=%s" % debugInputPath)

  curFolder = os.path.abspath(curFolder)
  # print("curFolder=%s" % curFolder)
  # here work:
  # . -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
  return curFolder

def isObjcMsgSendFuncName(funcName):
  """
  check function name is _objc_msgSend$xxx or not
  eg:
    "_objc_msgSend$arrayByAddingObjectsFromArray:" -> True, "arrayByAddingObjectsFromArray:"
    "_objc_msgSend$addObject:_AB00" -> True, "addObject:_AB00"
  """
  isOjbcMsgSend = False
  selectorStr = None
  # _objc_msgSend$arrangedSubviews
  # _objc_msgSend$arrayByAddingObjectsFromArray:
  # _objc_msgSend$arrangeFromView:toView:progress:forwardDirection:
  # objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+¸)$", funcName)
  # objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+)(?P<renamedAddrSuffix>_[A-Za-z0-9]+)?$", funcName)
  objcMsgSendMatch = re.match("^_*objc_msgSend\$(?P<selectorStr>[\w\:]+)$", funcName)
  # print("objcMsgSendMatch=%s" % objcMsgSendMatch)
  if objcMsgSendMatch:
    selectorStr = objcMsgSendMatch.group("selectorStr")
    # print("selectorStr=%s" % selectorStr)
    isOjbcMsgSend = True
  # print("isOjbcMsgSend=%s, selectorStr=%s" % (isOjbcMsgSend, selectorStr))
  return isOjbcMsgSend, selectorStr

def isObjcMsgSendFunction(curAddr):
  """
  check is default sub_XXX function or not from address
  """
  isObjcMsgSend = False
  curFuncName  = ida_getFunctionName(curAddr)
  # print("curFuncName=%s" % curFuncName)
  if curFuncName:
    isObjcMsgSend, selectorStr = isObjcMsgSendFuncName(curFuncName)
  return isObjcMsgSend, selectorStr


################################################################################
# IDA Util Class
################################################################################

class Operand:
  # Operand Type
  # https://hex-rays.com/products/ida/support/idapython_docs/idc.html#idc.get_operand_value
  o_void     = 0        # No Operand                           ----------
  o_reg      = 1        # General Register (al,ax,es,ds...)    reg
  o_mem      = 2        # Direct Memory Reference  (DATA)      addr
  o_phrase   = 3        # Memory Ref [Base Reg + Index Reg]    phrase
  o_displ    = 4        # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
  o_imm      = 5        # Immediate Value                      value
  o_far      = 6        # Immediate Far Address  (CODE)        addr
  o_near     = 7        # Immediate Near Address (CODE)        addr
  o_idpspec0 = 8        # Processor specific type
  o_idpspec1 = 9        # Processor specific type
  o_idpspec2 = 10       # Processor specific type
  o_idpspec3 = 11       # Processor specific type
  o_idpspec4 = 12       # Processor specific type
  o_idpspec5 = 13       # Processor specific type
                        # There can be more processor specific types

  # x86
  o_trreg  =       o_idpspec0      # trace register
  o_dbreg  =       o_idpspec1      # debug register
  o_crreg  =       o_idpspec2      # control register
  o_fpreg  =       o_idpspec3      # floating point register
  o_mmxreg  =      o_idpspec4      # mmx register
  o_xmmreg  =      o_idpspec5      # xmm register

  # arm
  o_reglist  =     o_idpspec1      # Register list (for LDM/STM)
  o_creglist  =    o_idpspec2      # Coprocessor register list (for CDP)
  o_creg  =        o_idpspec3      # Coprocessor register (for LDC/STC)
  o_fpreglist  =   o_idpspec4      # Floating point register list
  o_text  =        o_idpspec5      # Arbitrary text stored in the operand
  o_cond  =        o_idpspec5 + 1  # ARM condition as an operand

  # ppc
  o_spr  =         o_idpspec0      # Special purpose register
  o_twofpr  =      o_idpspec1      # Two FPRs
  o_shmbme  =      o_idpspec2      # SH & MB & ME
  o_crf  =         o_idpspec3      # crfield      x.reg
  o_crb  =         o_idpspec4      # crbit        x.reg
  o_dcr  =         o_idpspec5      # Device control register


  # addStr = "add"
  # addStr = "Add"
  offStr = "Off" # Offset=Index
  # valStr = "val"
  valStr = "Val"

  def __init__(self, operand, type, value):
    self.operand = operand
    self.type = type
    self.value = value

    # for o_displ / o_phrase
    self.baseReg = None
    self.indexReg = None
    # for o_displ
    self.displacement = None

    self._postInit()
  
  def _postInit(self):
    # print("_postInit")
    if self.isDispl():
      # o_displ    = 4        # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
      # [SP,#arg_18]
      # [X20,#0x50]
      # print("self.operand=%s" % self.operand)
      # displMatch = re.search("\[(?P<baseReg>\w+),(?P<displacement>#[\w\-\.]+)\]", self.operand)
      # [X9]
      displMatch = re.search("\[(?P<baseReg>\w+)(,(?P<displacement>#[\w\-\.]+))?\]", self.operand)
      # print("displMatch=%s" % displMatch)
      if displMatch:
        self.baseReg = displMatch.group("baseReg")
        # print("self.baseReg=%s" % self.baseReg)
        self.displacement = displMatch.group("displacement")
        # print("self.displacement=%s" % self.displacement)
    elif self.isPhrase():
      # o_phrase   = 3        # Memory Ref [Base Reg + Index Reg]    phrase
      # [X19,X8]
      # print("self.operand=%s" % self.operand)
      phraseMatch = re.search("\[(?P<baseReg>\w+),(?P<indexReg>\w+)\]", self.operand)
      # print("phraseMatch=%s" % phraseMatch)
      if phraseMatch:
        self.baseReg = phraseMatch.group("baseReg")
        # print("self.baseReg=%s" % self.baseReg)
        self.indexReg = phraseMatch.group("indexReg")
        # print("self.indexReg=%s" % self.indexReg)

  def __str__(self):
    valStr = ""
    if self.value <= 0:
      valStr = "%s" % self.value
    else:
      valStr = "0x%X" % self.value
    # curOpStr = "<Operand: op=%s,type=%d,val=%s>" % (self.operand, self.type, valStr)
    # curOpStr = "<Operand: op=%s,type=%d,val=%s, baseReg=%s,indexReg=%s,displ=%s>" % (self.operand, self.type, valStr, self.baseReg, self.indexReg, self.displacement)
    extraInfo = ""
    if self.isDispl():
      extraInfo = ",bsReg=%s,idxReg=%s,displ=%s" % (self.baseReg, self.indexReg, self.displacement)
    elif self.isPhrase():
      extraInfo = ",bsReg=%s,idxReg=%s" % (self.baseReg, self.indexReg)
    curOpStr = "<Operand: op=%s,type=%d,val=%s%s>" % (self.operand, self.type, valStr, extraInfo)
    # print("curOpStr=%s" % curOpStr)
    return curOpStr

  @staticmethod
  def listToStr(operandList):
    # operandStrList = []
    # for curOperand in operandList:
    #   if curOperand:
    #     curOperandStr = "%s" % curOperand
    #   else:
    #     curOperandStr = ""
    #   # print("curOperandStr=%s" % curOperandStr)
    #   operandStrList.append(curOperandStr)
    operandStrList = [str(eachOperand) for eachOperand in operandList]
    operandListAllStr = ", ".join(operandStrList)
    operandListAllStr = "[%s]" % operandListAllStr
    return operandListAllStr

  def isReg(self):
    return self.type == Operand.o_reg

  def isImm(self):
    return self.type == Operand.o_imm

  def isDispl(self):
    return self.type == Operand.o_displ

  def isPhrase(self):
    return self.type == Operand.o_phrase

  def isNear(self):
    return self.type == Operand.o_near

  def isIdpspec0(self):
    #   o_idpspec0 = 8        # Processor specific type
    return self.type == Operand.o_idpspec0

  def isValid(self):
    isDebug = False

    # isValidOperand = bool(self.operand)
    # print("isValidOperand=%s" % isValidOperand)
    # if isValidOperand:
    isValidOperand = False

    if isDebug:
      print("self.operand=%s" % self.operand)

    if self.operand:
      if self.isImm():
        # #0x20200A2C
        # #0x2020
        # #arg_20
        # isMatchImm = re.match("^#[0-9a-fA-FxX]+$", self.operand)
        # #-3.0
        # isMatchImm = re.match("^#\w+$", self.operand)
        isMatchImm = re.match("^#[\w\-\.]+$", self.operand)
        if isDebug:
          print("isMatchImm=%s" % isMatchImm)
        isValidOperand = bool(isMatchImm)
        if isDebug:
          print("isValidOperand=%s" % isValidOperand)
      elif self.isReg():
        # X0/X1
        # D8/D4
        # Special: XZR/WZR
        regNameUpper = self.operand.upper()
        # print("regNameUpper=%s" % regNameUpper)
        # isMatchReg = re.match("^[XD]\d+$", regNameUpper)
        # isMatchReg = re.match("^[XDW]\d+$", regNameUpper)
        isMatchReg = re.match("^([XDW]\d+)|(XZR)|(WZR)$", regNameUpper)
        if isDebug:
          print("isMatchReg=%s" % isMatchReg)
        isValidOperand = bool(isMatchReg)
        if isDebug:
          print("isValidOperand=%s" % isValidOperand)
        if not isValidOperand:
          isValidOperand = regNameUpper in ArmSpecialRegNameList
      elif self.isDispl():
        # o_displ    = 4        # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        # curOperand=<Operand: op=[SP,#arg_18],type=4,val=0x18>
        # if self.baseReg and (not self.indexReg) and self.displacement:
        # curOperand=<Operand: op=[X9],type=4,val=0x0>
        if isDebug:
          print("self.baseReg=%s, self.indexReg=%s, self.displacement=%s" % (self.baseReg, self.indexReg, self.displacement))

        if self.baseReg and (not self.indexReg):
          # Note: self.displacement is None / Not-None
          # TODO: add more type support, like indexReg not None
          isValidOperand = True
      elif self.isPhrase():
        # curOperand=<Operand: op=[X19,X8],type=3,val=0x94>
        if isDebug:
          print("self.baseReg=%s, self.indexReg=%s" % (self.baseReg, self.indexReg))
        if self.baseReg and self.indexReg:
          isValidOperand = True
      elif self.isNear():
        # o_near     = 7        # Immediate Near Address (CODE)        addr
        # curOperand=<Operand: op=_objc_copyWeak,type=7,val=0x1024ABBD0>
        if isDebug:
          print("self.value=%s" % self.value)

        if self.value:
          # jump to some (non 0) address -> consider is valid
          isValidOperand = True
      elif self.isIdpspec0():
        isValidOperand = True

    # print("isValidOperand=%s" % isValidOperand)

    # isValidType = self.type != Operand.o_void
    # isValidValue = self.value >= 0
    # isValidAll = isValidOperand and isValidType and isValidValue
    # isValidTypeValue = False
    # if self.isReg() or self.isImm():
    #   isValidTypeValue = self.value >= 0
    # elif self.isIdpspec0():
    #   isValidTypeValue = self.value == -1

    if self.isIdpspec0():
      isValidTypeValue = self.value == -1
    else:
      isValidType = self.type != Operand.o_void
      isValidValue = self.value >= 0
      isValidTypeValue = isValidType and isValidValue
    isValidAll = isValidOperand and isValidTypeValue

    if isDebug:
      print("Operand isValidAll=%s" % isValidAll)
    return isValidAll

  def isInvalid(self):
    return not self.isValid()
  
  @property
  def immVal(self):
    curImmVal = None
    if self.isImm():
      curImmVal = self.value
      # print("curImmVal=%s" % curImmVal)
    return curImmVal
  
  @property
  def immValHex(self):
    curImmValHex = ""
    if self.immVal != None:
      curImmValHex = "0x%X" % self.immVal
      # print("curImmValHex=%s" % curImmValHex)
    return curImmValHex

  @property
  def regName(self):
    curRegName = None
    if self.isReg():
      curRegName = self.operand
    return curRegName

  @property
  def contentStr(self):
    contentStr = ""
    if self.isReg():
      # print("isReg")
      contentStr = self.regName
    elif self.isImm():
      # print("isImm")
      # if 0 == self.immVal:
      # for 0 <= x < 8, not add 0x prefix, eg: 0x7 -> 7
      if (self.immVal >= 0) and (self.immVal < 8):
        # contentStr = "0"
        contentStr = "%X" % self.immVal
      else:
        contentStr = self.immValHex
    elif self.isIdpspec0():
        contentStr = self.operand
    elif self.isDispl():
        # [SP,#arg_18]
        # print("self.displacement=%s" % self.displacement)
        if self.displacement:
          displacementStr = ""
          if self.value != None:
            if (self.value >= 0) and (self.value < 8):
              displacementStr = "%X" % self.value
            else:
              displacementStr = "0x%X" % self.value
          # print("displacementStr=%s" % displacementStr)
          contentStr = "%s%s%s%s" % (self.baseReg, Operand.offStr, displacementStr, Operand.valStr)
        else:
          contentStr = "%s%s" % (self.baseReg, Operand.valStr)
    elif self.isPhrase():
      # [X19,X8]
      contentStr = "%s%s%s%s" % (self.baseReg, Operand.offStr, self.indexReg, Operand.valStr)

    # remove invalid char
    # <Operand: op=W0,UXTB,type=8,val=-1>
    # W0,UXTB -> W0UXTB
    contentStr = contentStr.replace(",", "")
    # X21,LSL#32
    # X8,ASR#29
    contentStr = contentStr.replace("#", "")

    # TODO: add more case

    # print("contentStr=%s" % contentStr)
    return contentStr

  @property
  def regIdx(self):
    curRegIdx = None
    if self.isReg():
      # TODO: extract reg idx, 
      # eg: X0 -> 0, X4 -> 4
      # note: additonal: D0 -> 0, D8 -> 8 ?
      curRegIdx = 0
    return curRegIdx


# class Instruction(object):
class Instruction:
  # toStr = "to"
  toStr = "To"
  # addStr = "add"
  addStr = "Add"

  def __init__(self, addr, name, operands):
    self.addr = addr
    self.disAsmStr = ida_getDisasmStr(addr)
    # print("self.disAsmStr=%s" % self.disAsmStr)
    self.name = name
    self.operands = operands

  def __str__(self):
    # operandsAllStr = Operand.listToStr(self.operands)
    # print("operandsAllStr=%s" % operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,name=%s,operands=%s>" % (self.addr, self.name, operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,disAsmStr=%s>" % (self.addr, self.disAsmStr)
    curInstStr = "<Instruction: 0x%X: %s>" % (self.addr, self.disAsmStr)
    # print("curInstStr=%s" % curInstStr)
    return curInstStr

  @staticmethod
  def listToStr(instList):
    instContentStrList = [str(eachInst) for eachInst in instList]
    instListAllStr = ", ".join(instContentStrList)
    instListAllStr = "[%s]" % instListAllStr
    return instListAllStr

  @staticmethod
  def parse(addr):
    isDebug = False
    # # if addr == 0x10235D610:
    # # if addr == 0x1002B8340:
    # if addr == 0x102390B18:
    #   isDebug = True
    # isDebug = True

    if isDebug:
      print("Instruction: parsing 0x%X" % addr)
    parsedInst = None

    instName = idc.print_insn_mnem(addr)
    if isDebug:
      print("instName=%s" % instName)

    curOperandIdx = 0
    curOperandVaild = True
    operandList = []
    while curOperandVaild:
      if isDebug:
        logSubSub("[%d]" % curOperandIdx)
      curOperand = idc.print_operand(addr, curOperandIdx)
      if isDebug:
        print("curOperand=%s" % curOperand)
      curOperandType = idc.get_operand_type(addr, curOperandIdx)
      if isDebug:
        print("curOperandType=%d" % curOperandType)
      curOperandValue = idc.get_operand_value(addr, curOperandIdx)
      if isDebug:
        print("curOperandValue=%s=0x%X" % (curOperandValue, curOperandValue))
      curOperand = Operand(curOperand, curOperandType, curOperandValue)
      if isDebug:
        print("curOperand=%s" % curOperand)
      if curOperand.isValid():
        operandList.append(curOperand)
      else:
        if isDebug:
          print("End of operand for invalid %s" % curOperand)
        curOperandVaild = False

      if isDebug:
        print("curOperandVaild=%s" % curOperandVaild)
      curOperandIdx += 1

    if operandList:
      parsedInst = Instruction(addr=addr, name=instName, operands=operandList)
    if isDebug:
      print("parsedInst=%s" % parsedInst)
      print("operandList=%s" % Operand.listToStr(operandList))
    return parsedInst

  def isInst(self, instName):
    isMatchInst = False
    if self.name:
      if (instName.lower() == self.name.lower()):
        isMatchInst = True
    return isMatchInst

  @property
  def contentStr(self):
    """
    convert to meaningful string of Instruction real action / content
    """
    contentStr = ""

    isDebug = False
    # isDebug = True

    if isDebug:
      print("self=%s" % self)

    operandNum = len(self.operands)
    if isDebug:
      print("operandNum=%s" % operandNum)
    
    isPairInst = self.isStp() or self.isLdp()
    if isDebug:
      print("isPairInst=%s" % isPairInst)
    if not isPairInst:
      if operandNum >= 2:
        srcOperand = self.operands[1]
        if isDebug:
          print("srcOperand=%s" % srcOperand)
        srcOperandStr = srcOperand.contentStr
        if isDebug:
          print("srcOperandStr=%s" % srcOperandStr)
        dstOperand = self.operands[0]
        if isDebug:
          print("dstOperand=%s" % dstOperand)
        dstOperandStr = dstOperand.contentStr
        if isDebug:
          print("dstOperandStr=%s" % dstOperandStr)

    if self.isMov() or self.isFmov():
      # MOV X0, X24
      # FMOV D4, #-3.0

      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
        # print("contentStr=%s" % contentStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of MOV/FMOV")
    elif self.isAdd() or self.isFadd():
      # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
      # # print("is ADD: self=%s" % self)
      # instName = self.name
      # # print("instName=%s" % instName)
      # instOperandList = self.operands
      # # print("instOperandList=%s" % Operand.listToStr(instOperandList))
      if operandNum == 3:
        # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
        extracOperand = self.operands[2]
        # print("extracOperand=%s" % extracOperand)
        extraOperandStr = extracOperand.contentStr
        # print("extraOperandStr=%s" % extraOperandStr)
        contentStr = "%s%s%s%s%s" % (srcOperandStr, Instruction.addStr, extraOperandStr, Instruction.toStr, dstOperandStr)

      # TODO: add case operand == 2
    elif self.isLdr():
      # LDR X0, [SP,#arg_18];
      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of LDR")
    elif self.isStr():
      # STR XZR, [X19,X8]
      if operandNum == 2:
        contentStr = "%s%s%s" % (dstOperandStr, Instruction.toStr, srcOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of STR")
    elif self.isStp():
      # <Instruction: 0x10235D6B4: STP X8, X9, [SP,#arg_18]>
      if operandNum == 3:
        srcOperand1 = self.operands[0]
        if isDebug:
          print("srcOperand1=%s" % srcOperand1)
        srcOperand1Str = srcOperand1.contentStr
        if isDebug:
          print("srcOperand1Str=%s" % srcOperand1Str)
        srcOperand2 = self.operands[1]
        if isDebug:
          print("srcOperand2=%s" % srcOperand2)
        srcOperand2Str = srcOperand2.contentStr
        if isDebug:
          print("srcOperand2Str=%s" % srcOperand2Str)

        dstOperand = self.operands[2]
        if isDebug:
          print("dstOperand=%s" % dstOperand)
        dstOperandStr = dstOperand.contentStr
        if isDebug:
          print("dstOperandStr=%s" % dstOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperand1Str, srcOperand2Str, Instruction.toStr, dstOperandStr)
    elif self.isLdp():
      # <Instruction: 0x10235D988: LDP D0, D1, [X8]>
      # <Instruction: 0x10235D98C: LDP D2, D3, [X8,#0x10]>
      if operandNum == 3:
        dstOperand1 = self.operands[0]
        if isDebug:
          print("dstOperand1=%s" % dstOperand1)
        dstOperand1Str = dstOperand1.contentStr
        if isDebug:
          print("dstOperand1Str=%s" % dstOperand1Str)
        dstOperand2 = self.operands[1]
        if isDebug:
          print("dstOperand2=%s" % dstOperand2)
        dstOperand2Str = dstOperand2.contentStr
        if isDebug:
          print("dstOperand2Str=%s" % dstOperand2Str)

        srcOperand = self.operands[2]
        if isDebug:
          print("srcOperand=%s" % srcOperand)
        srcOperandStr = srcOperand.contentStr
        if isDebug:
          print("srcOperandStr=%s" % srcOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperand1Str, dstOperand2Str)

    # TODO: add other Instruction support: SUB/STR/...
    if isDebug:
      print("contentStr=%s" % contentStr)
    return contentStr

  def isMov(self):
    return self.isInst("MOV")

  def isFmov(self):
    return self.isInst("FMOV")

  def isRet(self):
    return self.isInst("RET")

  def isB(self):
    return self.isInst("B")

  def isBr(self):
    return self.isInst("BR")

  def isBranch(self):
    # TODO: support more: BRAA / ...
    return self.isB() or self.isBr()

  def isAdd(self):
    return self.isInst("ADD")

  def isFadd(self):
    return self.isInst("FADD")

  def isSub(self):
    return self.isInst("SUB")

  def isStr(self):
    return self.isInst("STR")

  def isStp(self):
    return self.isInst("STP")

  def isLdp(self):
    return self.isInst("LDP")

  def isLdr(self):
    return self.isInst("LDR")

################################################################################
# Current Project Functions
################################################################################

def isFuncSizeValid(funcSize):
  # note: not include invalid size: 0
  return (funcSize > 0) and (funcSize <= MAX_INSTRUCTION_SIZE)

def isAllMovInst(instructionList):
  """
  Check is all MOV/FMOV instruction
  """
  isAllMov = True
  for eachInst in instructionList:
    isMovLikeInst = eachInst.isMov() or eachInst.isFmov()
    if not isMovLikeInst:
      isAllMov = False
      break
  return isAllMov

def isPrologueEpilogueReg(regName):
  """
  Check is Prologue/Epilogue register
  eg:
    "X28" -> True
    "D8" -> True
  """
  # print("regName=%s" % regName)
  regNameUpper = regName.upper()
  # print("regNameUpper=%s" % regNameUpper)
  isPrlgEplg = regNameUpper in PrologueEpilogueRegList
  # print("isPrlgEplg=%s" % isPrlgEplg)
  return isPrlgEplg

def isPrologueEpilogueOperand(curOperand):
  """
  Check is Prologue/Epilogue Operand
  eg:
    <Operand: op=X28,type=1,val=0x9D> -> True
  """
  isPrlgEplgOp = False
  opIsReg = curOperand.isReg()
  # print("opIsReg=%s" % opIsReg)
  if opIsReg:
    regName = curOperand.operand
    # print("regName=%s" % regName)
    isPrlgEplgOp = isPrologueEpilogueReg(regName)

  # print("isPrlgEplgOp=%s" % isPrlgEplgOp)
  return isPrlgEplgOp

def isAllPrologueStp(instructionList):
  """
  Check is all STP instruction of prologue
  eg:
    STP X28, X27, [SP,#arg_70]
  """
  isAllPrlgStp = True
  for eachInst in instructionList:
    # print("eachInst=%s" % eachInst)
    isStp = eachInst.isStp()
    if isStp:
      # check operand register match or not
      curOperands = eachInst.operands
      # print("curOperands=%s" % curOperands)
      operandNum = len(curOperands)
      # print("operandNum=%s" % operandNum)
      if operandNum == 3:
        operand1 = curOperands[0]
        operand2 = curOperands[1]
        # print("operand1=%s, operand2=%s" % (operand1, operand2))
  
        # # for debug
        # operand3 = curOperands[2]
        # print("operand3=%s" % operand3)
  
        op1IsPrlgEplg = isPrologueEpilogueOperand(operand1)
        op2IsPrlgEplg = isPrologueEpilogueOperand(operand2)
        # print("op1IsPrlgEplg=%s, op2IsPrlgEplg=%s" % (op1IsPrlgEplg, op2IsPrlgEplg))
        isAllPrlgStp = op1IsPrlgEplg and op2IsPrlgEplg
      else:
        isAllPrlgStp = False  
    else:
      isAllPrlgStp = False
      break

  # print("isAllPrlgStp=%s" % isAllPrlgStp)
  return isAllPrlgStp

def checkAllMovThenRet(instructionList):
  isAllMovThenRet = False

  lastInst = instructionList[-1]
  # print("lastInst=%s" % lastInst)
  lastIsRet = lastInst.isRet()
  # print("lastIsRet=%s" % lastIsRet)
  if lastIsRet:
    instListExceptLast = instructionList[:-1]
    # print("instListExceptLast=%s" % instListExceptLast)
    isAllMov = isAllMovInst(instListExceptLast)
    print("isAllMov=%s" % isAllMov)
    isAllMovThenRet = lastIsRet and isAllMov

  # print("isAllMovThenRet=%s" % isAllMovThenRet)
  return isAllMovThenRet

def checkAllMovThenBranch(instructionList):
  isAllMovThenBranch = False

  lastInst = instructionList[-1]
  # print("lastInst=%s" % lastInst)
  lastIsBranch = lastInst.isBranch()
  # print("lastIsBranch=%s" % lastIsBranch)
  if lastIsBranch:
    instListExceptLast = instructionList[:-1]
    # print("instListExceptLast=%s" % instListExceptLast)
    isAllMov = isAllMovInst(instListExceptLast)
    # print("isAllMov=%s" % isAllMov)
    isAllMovThenBranch = lastIsBranch and isAllMov

  # print("isAllMovThenBranch=%s" % isAllMovThenBranch)
  return isAllMovThenBranch

def checkPrologue(instructionList):
  isPrologue = False

  lastInst = instructionList[-1]
  # print("lastInst=%s" % lastInst)
  lastIsRet = lastInst.isRet()
  # print("lastIsRet=%s" % lastIsRet)
  if lastIsRet:
    instListExceptLast = instructionList[:-1]
    # print("instListExceptLast=%s" % instListExceptLast)
    isAllStp = isAllPrologueStp(instListExceptLast)
    # print("isAllStp=%s" % isAllStp)
    isPrologue = lastIsRet and isAllStp

  # print("isPrologue=%s" % isPrologue)
  return isPrologue

def isNeedProcessFunc(curFuncAddr):
  isNeedProcess = False
  curFuncSize = ida_getFunctionSize(curFuncAddr)
  # print("curFuncSize=%s" % curFuncSize)
  # if curFuncSize <= MAX_INSTRUCTION_SIZE:
  isValidSize = isFuncSizeValid(curFuncSize)
  # print("isValidSize=%s" % isValidSize)
  if isValidSize:
    isDefaultSubFunc, funcName = isDefaultSubFunction(curFuncAddr)
    # print("isDefaultSubFunc=%s, funcName=%s" % (isDefaultSubFunc, funcName))
    if isDefaultSubFunc:
      isNeedProcess = True

    if not isNeedProcess:
      isObjcMsgSend, selectorStr = isObjcMsgSendFunction(curFuncAddr)
      # print("isObjcMsgSend=%s, selectorStr=%s" % (isObjcMsgSend, selectorStr))
      if isObjcMsgSend:
        # isNeedProcess = True
        # for has processed -> not process
        renamedAddrSuffixMatch = re.match(".+_[A-Z0-9]{4,20}$", selectorStr)
        # print("renamedAddrSuffixMatch=%s" % renamedAddrSuffixMatch)
        if not renamedAddrSuffixMatch:
          isNeedProcess = True

  # print("isNeedProcess=%s" % isNeedProcess)
  return isNeedProcess

def generateFirstParaName(selectorFirstPart):
  """
  generate first parameter name from selector first part
  eg:
    "arrayByAddingObjectsFromArray" -> "someArray"
    "wa_alignedCenterFromCenter" -> "someCenter"
    "arrangeFromView" -> "someView"
    "postIdentityChangeNotificationForDeviceJIDs" -> deviceJIDs
    "addObject" -> "someObject"
    "pickerMode" -> "pickerMode"
  """
  firstParaName = ""
  keywordMatch = re.search("(From|from|Add|add|For)(?P<keyword>[A-Z][a-z0-9_]+)$", selectorFirstPart)
  # print("keywordMatch=%s" % keywordMatch)
  if keywordMatch:
    keyword = keywordMatch.group("keyword")
    # print("keyword=%s" % keyword)
    firstParaName = "some%s" % keyword

  if not firstParaName:
    firstParaName = selectorFirstPart

  # print("selectorFirstPart=%s -> firstParaName=%s" % (selectorFirstPart, firstParaName))
  return firstParaName


def generateInstContentListStr(instructionList, isFirstDigitAddPrefix=True):
  # print("instructionList=%s, isFirstDigitAddPrefix=%s" % (instructionList, isFirstDigitAddPrefix))
  # print("instructionList=%s, isFirstDigitAddPrefix=%s" % (Instruction.listToStr(instructionList), isFirstDigitAddPrefix))

  instContentStrList = []
  for eachInst in instructionList:
    eachInstContentStr = eachInst.contentStr
    # print("eachInstContentStr=%s" % eachInstContentStr)
    instContentStrList.append(eachInstContentStr)

  allInstContentStr = "_".join(instContentStrList)
  # print("allInstContentStr=%s" % allInstContentStr)

  prefixStr = ""
  if isFirstDigitAddPrefix:
    isFisrtIsDigit = re.match("^\d+", allInstContentStr)
    # print("isFisrtIsDigit=%s" % isFisrtIsDigit)
    if isFisrtIsDigit:
      prefixStr = "func_"

  allInstContentStr = "%s%s" % (prefixStr, allInstContentStr)
  # print("allInstContentStr=%s" % allInstContentStr)

  return allInstContentStr

def generateBranchName(branchInst):
  isSupport = True
  branchFunc = None
  errMsg = ""

  branchInstName = branchInst.name
  # print("branchInstName=%s" % branchInstName)
  branchInstOperands = branchInst.operands
  # print("branchInstOperands=%s" % branchInstOperands)
  targetOperand = branchInstOperands[0]
  # print("targetOperand=%s" % targetOperand)
  # targetOperand=<Operand: op=_objc_msgSend$initWithName_protocolString_,type=7,val=0xF9DDC0>
  # branchFunc = targetOperand.value
  branchFunc = targetOperand.operand
  # print("branchFunc=%s" % branchFunc)
  branchType = targetOperand.type
  # print("branchType=%s" % branchType)
  if branchType == Operand.o_reg:
    # BR X27
    # branchFunc = "Jump%s" % branchFunc
    branchFunc = "%s%s" % (branchInstName, branchFunc)
  else:
    isDefSubFunc, subAddrStr = isDefaultSubFuncName(branchFunc)
    # print("isDefSubFunc=%s, subAddrStr=%s" % (isDefSubFunc, subAddrStr))
    isReserved_loc, locAddrStr = isReservedPrefix_loc(branchFunc)
    # print("isReserved_loc=%s, locAddrStr=%s" % (isReserved_loc, locAddrStr))
    if isDefSubFunc:
      isSupport = False
      branchFunc = None
      defSubFuncName = "sub_%s" % subAddrStr
      errMsg = "Current not support for jump to %s" % defSubFuncName
      # TODO: add branch jump to sub_xxx
    elif isReserved_loc:
      # branchFunc = None
      branchFunc = "JmpLoc%s" % locAddrStr
    else:
      # _calloc_2EA8
      # _objc_msgSend
      # _objc_release
      # _objc_storeStrong_39D0
      # objc_msgSend$initWithName_protocolString_
      # _objc_msgSend$addObject__AB00
      # remove leading _
      branchFunc = re.sub("^_+", "", branchFunc)
      # print("branchFunc=%s" % branchFunc)
      # remove ending _
      branchFunc = re.sub("_+$", "", branchFunc)
      # print("branchFunc=%s" % branchFunc)
      # remove last 4 or allAddr part if exist (previous self manual added)
      branchFunc = re.sub("_+[0-9A-Fa-f]{3,20}$", "", branchFunc)
  # print("isSupport=%s, branchFunc=%s, errMsg=%s" % (isSupport, branchFunc, errMsg))
  return isSupport, branchFunc, errMsg


def checkAndGenerateInstListContentStr(instructionList):
  isSupportAllInst = True
  instListContentStr = ""
  firstUnsupportInst = None

  instContentStrList = []
  for eachInst in instructionList:
    # print("eachInst=%s" % eachInst)
    instContentStr = eachInst.contentStr
    # print("instContentStr=%s" % instContentStr)
    if instContentStr:
      instContentStrList.append(instContentStr)
    else:
      isSupportAllInst = False
      firstUnsupportInst = eachInst
      # print("firstUnsupportInst=%s" % firstUnsupportInst)
      break
  
  if isSupportAllInst:
    instListContentStr = "_".join(instContentStrList)
    # print("instListContentStr=%s" % instListContentStr)
    return isSupportAllInst, instListContentStr
  else:
    return isSupportAllInst, firstUnsupportInst


################################################################################
# Main
################################################################################

idaVersion = idaapi.IDA_SDK_VERSION
print("IDA Version: %s" % idaVersion)

curBinFilename = ida_nalt.get_root_filename()
print("curBinFilename=%s" % curBinFilename)

if isExportResult:
  curDateTimeStr = getCurDatetimeStr()
  print("curDateTimeStr=%s" % curDateTimeStr)

  if not outputFolder:
    outputFolder = ida_getCurrentFolder()
    print("outputFolder=%s" % outputFolder)

# # # for debug
# # ---------- allMovThenRet ----------
# # # toProcessFuncAddrList = [0x10235F980, 0x1023A2534, 0x1023A255C, 0x10235F998]
# # # toProcessFuncAddrList = [0x1023A2578]
# # # toProcessFuncAddrList = [0x3B4E28]
# # # toProcessFuncAddrList = [0x3B4EC4, 0x3B4ED4, 0x3B5068, 0x3B7140, 0x3B9978]
# # # toProcessFuncAddrList = [0x4C491C, 0x4C499C, 0x4C49E0, 0x4C49D4]
# # # toProcessFuncAddrList = [0x4C49C4, 0x4C5E0C, 0x4C5E00, 0x4C7E0C, 0x4C7FB8]
# # # toProcessFuncAddrList = [0x4C800C, 0x4C8038]
# # toProcessFuncAddrList = [0x4C9D34, 0x4C9D50, 0x4D0550]
# # toProcessFuncAddrList = [0xF147B0]
# # ---------- allMovThenBranch ----------
# toProcessFuncAddrList = [
#   # 0x3B4E18, 0xF0B15C, 0xF0CB44, 0xF33348,
#   0xF332C0, 0xF0AED4, 0xF0BE60, 0xF147DC, 0xF0AEB0, 0xF0AF04, 0xD3F9F4,  
# ]# SharedModules
# # toProcessFuncAddrList = [0x10235C798, 0x10235C6B0, 0x10235D56C, 0x10163D5C4, 0x10163D5D8, 0x10163D5E0] # WhatsApp
# toProcessFuncAddrList = [0x100006A00, 0x100046B88, 0x1001A99FC, 0x1004039EC] # WhatsApp
# toProcessFuncAddrList = [0xF0AED4] # SharedModules
# toProcessFuncAddrList = [0x10235D3C0, 0x10235D3A8, 0x10235D390, 0x10235D374] # WhatsApp
# toProcessFuncAddrList = [0xF0C694, 0xF0CA08, 0xF0CA3C] # SharedModules
# toProcessFuncAddrList = [0x10235D574, 0x10235D60C, 0x10235D6B4, 0x102475804, 0x1024757E4, 0x10247B4C0] # WhatsApp
# toProcessFuncAddrList = [0x102475804] # WhatsApp
# toProcessFuncAddrList = [0x10235D324, 0x10235D35C] # WhatsApp
# toProcessFuncAddrList = [0x1002B8338] # WhatsApp
# toProcessFuncAddrList = [0xF2E54C, 0xF2E510, ] # SharedModules
# toProcessFuncAddrList = [0x102390B18] # WhatsApp
# toProcessFuncAddrList = [0x10235D598, 0x10235D5E0, 0x10235D99C, 0x10235D9A8] # WhatsApp
# toProcessFuncAddrList = [0x10235D5B0, 0x10235D69C, 0x10235DA7C] # WhatsApp
# toProcessFuncAddrList = [0xF2E534, 0xF2E37C, 0xF2E36C, 0xF2E488] # SharedModules
# toProcessFuncAddrList = [0xF2E488] # SharedModules
# toProcessFuncAddrList = [0x10235D6B4, 0x10235D69C, 0x10235D988, 0x10247B4C0] # WhatsApp
# toProcessFuncAddrList = [0x58FB08, 0x504634, 0x504644, 0x50462C, 0x503948, 0x503958, 0x5035BC, 0x5035AC, 0x5035A4, 0x500188] # SharedModules

# # for objc_msgSend
# # toProcessFuncAddrList = [0x1024D0000, 0x1024CFFA0, 0x1024CFF80, 0x1024CAB00] # WhatsApp
# # toProcessFuncAddrList = [0x103EF20, 0x103EF40, 0x103EF60, 0x103EF80, 0x103EFA0, 0x103EFC0, 0x103EFE0, 0xFCE9A0, 0xFCE980, 0xFCE960, 0xF62140] # SharedModules
# toProcessFuncAddrList = [0xF5DD20] # SharedModules
# allFuncAddrList = toProcessFuncAddrList

# normal code
allFuncAddrList = ida_getFunctionAddrList()

allFuncAddrListNum = len(allFuncAddrList)
print("allFuncAddrListNum=%d" % allFuncAddrListNum)
toProcessFuncAddrList = []
for curNum, eachFuncAddr in enumerate(allFuncAddrList, start=1):
  logSub("[%d] %s" % (curNum, eachFuncAddr))
  isNeedProcess = isNeedProcessFunc(eachFuncAddr)

  # # for debug:
  # isNeedProcess = True

  if isNeedProcess:
    toProcessFuncAddrList.append(eachFuncAddr)
    # print("+ [0x%X]" % eachFuncAddr)

toProcessFuncAddrListNum = len(toProcessFuncAddrList)
print("toProcessFuncAddrListNum=%d" % toProcessFuncAddrListNum)

toRenameNum = 0
renameOkNum = 0
renameFailNum = 0

toChangeTypeNum = 0
changeTypeOkNum = 0
changeTypeFailNum = 0

if isExportResult:
  resultDict = {}

  okList = []
  failList = []

for curNum, funcAddr in enumerate(toProcessFuncAddrList, start=1):
  funcAddrStr = "0x%X" % funcAddr
  logMain("[%08d/%08d] %s" % (curNum, toProcessFuncAddrListNum, funcAddrStr))

  funcSize = ida_getFunctionSize(funcAddr)
  if not isFuncSizeValid(funcSize):
    print("Omit [%s] for invalid function size %d" % (funcAddrStr, funcSize))
    continue

  funcName = ida_getFunctionName(funcAddr)

  oldFuncType = None
  newFuncType = None
  paraObj = "id curObj"
  paraSelector = None
  retType = "id"

  funcNameMainPart = None
  newFuncName = None
  retryFuncName = None

  allAddrStr = "%X" % funcAddr
  # print("allAddrStr=%s" % allAddrStr)
  last4AddrStr = allAddrStr[-4:]
  # print("last4AddrStr=%s" % last4AddrStr)

  isObjcMsgSend, selectorStr = isObjcMsgSendFuncName(funcName)
  # print("isObjcMsgSend=%s, selectorStr=%s" % (isObjcMsgSend, selectorStr))
  if isObjcMsgSend:
    # note: here funcName is mandatory for change type, but actually is useless -> will not change to new name
    notUseNewFuncName = funcName
    # makesure name is valid
    notUseNewFuncName = re.sub("\W", "_", notUseNewFuncName)
    # print("notUseNewFuncName=%s" % notUseNewFuncName)

    funcNameMainPart = funcName
    # print("funcNameMainPart=%s" % funcNameMainPart)
    oldFuncType = idc.get_type(funcAddr)
    # oldFuncType=id(void *, const char *, ...)
    # print("oldFuncType=%s" % oldFuncType)
    newSelectorStr = selectorStr.replace(":", "_")
    # print("newSelectorStr=%s" % newSelectorStr)
    paraSelector = "const char * %s" % newSelectorStr
    # print("paraSelector=%s" % paraSelector)
    paramNum = selectorStr.count(":")
    # print("paramNum=%s" % paramNum)
    newValidParaList = []
    if paramNum == 0:
      newFuncType = "%s %s(%s, %s)" % (retType, notUseNewFuncName, paraObj, paraSelector)
      # print("newFuncType=%s" % newFuncType)
    else:
      paraList = selectorStr.split(":")
      # print("paraList=%s" % paraList)
      # ['arrayByAddingObjectsFromArray', '']
      # ['arrangeFromView', 'toView', 'progress', 'forwardDirection', '']
      # remove last empty
      lastItem = paraList[-1]
      # print("lastItem=%s" % lastItem)
      if not lastItem:
        paraList.pop(-1)
        # print("paraList=%s" % paraList)
      selectorFirstPart = paraList[0]
      # print("selectorFirstPart=%s" % selectorFirstPart)
      firstParaName = generateFirstParaName(selectorFirstPart)
      # print("firstParaName=%s" % firstParaName)
      newParaList = copy.deepcopy(paraList)
      # print("newParaList=%s" % newParaList)
      newParaList[0] = firstParaName
      # print("newParaList=%s" % newParaList)
      # process system reserved string, eg: class, id, ...
      for eachPara in newParaList:
        # print("eachPara=%s" % eachPara)

        # # for debug
        # eachPara = "class"

        if eachPara in IdaReservedStr:
          firstChar = eachPara[0]
          # print("firstChar=%s" % firstChar)
          firstCharUpper = firstChar.upper()
          # print("firstCharUpper=%s" % firstCharUpper)
          restChars = eachPara[1:]
          # print("restChars=%s" % restChars)
          validPara = "the%s%s" % (firstCharUpper, restChars)
        else:
          validPara = eachPara

        # print("validPara=%s" % validPara)
        newValidParaList.append(validPara)
    # print("newValidParaList=%s" % newValidParaList)

    newParaTypeNameList = []
    newParaTypeNameList.append(paraObj)
    newParaTypeNameList.append(paraSelector)
    for eachValidPara in newValidParaList:
      eachParaType = "id"
      eachParaStr = "%s %s" % (eachParaType, eachValidPara)
      newParaTypeNameList.append(eachParaStr)
    # print("newParaTypeNameList=%s" % newParaTypeNameList)
    newAllParaStr = ", ".join(newParaTypeNameList)
    # print("newAllParaStr=%s" % newAllParaStr)
    newFuncType = "%s %s(%s)" % (retType, notUseNewFuncName, newAllParaStr)
    # print("newFuncType=%s" % newFuncType)
  else:
    # process each instrunction and generate new function name
    funcEndAddr = ida_getFunctionEndAddr(funcAddr)

    if isVerbose:
      print("funcName=%s, funcSize=%d=0x%X, funcEndAddr=0x%X" % (funcName, funcSize, funcSize, funcEndAddr))

    isNeedOmitCurrent = False

    # isAllMovThenRet = False
    # isAllMovThenBranch = False
    # isPrologue = False

    funcNamePrefix = ""

    disAsmInstList = []
    for curFuncAddr in range(funcAddr, funcEndAddr, SINGLE_INSTRUCTION_SIZE):
      if isVerbose:
        logSub("[0x%X]" % curFuncAddr)
      newInst = Instruction.parse(curFuncAddr)
      if isVerbose:
        print("newInst=%s" % newInst)
      if newInst:
        disAsmInstList.append(newInst)
      else:
        instDisasmStr = ida_getDisasmStr(curFuncAddr)
        instInfoStr = "[0x%X] %s" % (curFuncAddr, instDisasmStr)
        if isFailForUnsupportInstruction:
          isNeedOmitCurrent = True
          print("Omit for found Invalid/Unsupported instruction: %s" % instInfoStr)
          break
        else:
          # just omit for Invalid/Unsupport instruction and continue process
          print("Found Invalid/Unsupported instruction: %s" % instInfoStr)

    if isNeedOmitCurrent:
      continue

    if isVerbose:
      instDisasmStrList = Instruction.listToStr(disAsmInstList)
      print("instDisasmStrList=%s" % instDisasmStrList)

    isPrologue = checkPrologue(disAsmInstList)
    if isVerbose:
      print("isPrologue=%s" % isPrologue)
    if isPrologue:
      funcNameMainPart = "prologue"
      newFuncName = "%s_%s" % (funcNameMainPart, allAddrStr)
      retryFuncName = None
    
    if not newFuncName:
      lastInst = disAsmInstList[-1]
      # print("lastInst=%s" % lastInst)
      lastIsRet = lastInst.isRet()
      # print("lastIsRet=%s" % lastIsRet)
      lastIsBranch = lastInst.isBranch()
      # print("lastIsBranch=%s" % lastIsBranch)
      if lastIsRet:
        funcNamePrefix = ""
      elif lastIsBranch:
        isSupport, branchFunc, errMsg = generateBranchName(lastInst)
        if isSupport:
          funcNamePrefix = branchFunc
        else:
          print("Omit [%s] for %s" % (funcAddrStr, errMsg))
          continue
      
      if isVerbose:
        print("funcNamePrefix=%s" % funcNamePrefix)

      instListExceptLast = disAsmInstList[0:-1]
      if isVerbose:
        # print("instListExceptLast=%s" % instListExceptLast)
        print("instListExceptLast=%s" % Instruction.listToStr(instListExceptLast))

      if instListExceptLast:
        isAllInstSupport, retValue = checkAndGenerateInstListContentStr(instListExceptLast)
        if isVerbose:
          print("isAllInstSupport=%s, retValue=%s" % (isAllInstSupport, retValue))

        if isAllInstSupport:
          instContentStr = retValue
          if funcNamePrefix:
            funcNameMainPart = "%s_%s" % (funcNamePrefix, instContentStr)
          else:
            funcNameMainPart = instContentStr
        else:
          firstUnsupportInst = retValue
          print("Fist unsupported instruction: %s" % firstUnsupportInst)
      else:
        print("Only 1 instrunction")
        funcNameMainPart = funcNamePrefix

      if isVerbose:
        print("funcNameMainPart=%s" % funcNameMainPart)
      if funcNameMainPart:
        isFisrtIsDigit = re.match("^\d+", funcNameMainPart)
        if isVerbose:
          print("isFisrtIsDigit=%s" % isFisrtIsDigit)
        if isFisrtIsDigit:
          funcNameMainPart = "func_%s" % funcNameMainPart
      if isVerbose:
        print("funcNameMainPart=%s" % funcNameMainPart)

  if funcNameMainPart:
    newFuncName = "%s_%s" % (funcNameMainPart, last4AddrStr)
    retryFuncName = "%s_%s" % (funcNameMainPart, allAddrStr)

  # # for debug
  # print("Test to rename: [0x%X] %s, %s" % (funcAddr, newFuncName, retryFuncName))

  if isExportResult:
    okItemDict = {}
    failItemDict = {}

  if newFuncName:
    toRenameNum += 1
    isRenameOk, renamedName = ida_rename(funcAddr, newFuncName, retryFuncName)
    if isVerbose:
      print("isRenameOk=%s, renamedName=%s" % (isRenameOk, renamedName))
    if isRenameOk:
      renameOkNum += 1
      print("renamed: [0x%X] %s -> %s" % (funcAddr, funcName, renamedName))
      if isExportResult:
        okItemDict["address"] = funcAddrStr
        # okItemDict["oldName"] = funcName
        # okItemDict["newName"] = renamedName
        okItemDict["name"] = {
          "old": funcName,
          "new": renamedName
        }
    else:
      print("! rename fail for [0x%X] %s -> %s or %s" % (funcAddr, funcName, renamedName, retryFuncName))
      renameFailNum += 1
      if isExportResult:
        failItemDict["address"] = funcAddrStr
        # failItemDict["oldName"] = funcName
        # failItemDict["newName"] = newFuncName
        # failItemDict["retryName"] = retryFuncName
        failItemDict["name"] = {
          "old": funcName,
          "new": newFuncName,
          "retry": retryFuncName,
        }

  if newFuncType:
    toChangeTypeNum += 1

    # # for debug
    # print("Test to change type: [0x%X] %s -> %s" % (funcAddr, oldFuncType, newFuncType))

    # # for debug: no change type
    # newFuncType = oldFuncType

    setTypeRet = idc.SetType(funcAddr, newFuncType)
    # print("type(setTypeRet)=%s" % type(setTypeRet)) # bool
    if isVerbose:
      print("setTypeRet=%s" % setTypeRet)
    # if setTypeRet == 1:
    if setTypeRet:
      changeTypeOkNum += 1
      print("SetType OK [0x%X] %s -> %s" % (funcAddr, oldFuncType, newFuncType))

      if isExportResult:
        okItemDict["address"] = funcAddrStr
        # okItemDict["oldType"] = oldFuncType
        # okItemDict["newType"] = newFuncType
        okItemDict["type"] = {
          "old": oldFuncType,
          "new": newFuncType
        }
    else:
      changeTypeFailNum += 1
      print("! SetType failed [0x%X] %s -> %s" % (funcAddr, oldFuncType, newFuncType))
      if isExportResult:
        failItemDict["address"] = funcAddrStr
        # failItemDict["oldType"] = oldFuncType
        # failItemDict["newType"] = newFuncType
        # failItemDict["setTypeRet"] = setTypeRet
        failItemDict["type"] = {
          "old": oldFuncType,
          "new": newFuncType,
          "setTypeRet": setTypeRet,
        }

  if isExportResult:
    if okItemDict:
      okList.append(okItemDict)
  
    if failItemDict:
      failList.append(failItemDict)

logMain("Summary Info")
print("Total Functions num: %d" % len(allFuncAddrList))
print("To process function num: %d" % toProcessFuncAddrListNum)
print("  To rename num: %d" % toRenameNum)
print("    OK num: %d" % renameOkNum)
print("    fail num: %d" % renameFailNum)
print("  To change type num: %d" % toChangeTypeNum)
print("    OK num: %d" % changeTypeOkNum)
print("    fail num: %d" % changeTypeFailNum)

if isExportResult:
  logMain("Export result to file")

  resultDict = {
    "ok": okList,
    "fail": failList,
  }

  # outputFilename = "IDA_renamedResult_%s.json" % curDateTimeStr
  outputFilename = "%s_IdaRenamedResult_%s.json" % (curBinFilename, curDateTimeStr)
  # print("outputFilename=%s" % outputFilename)
  outputFullPath = os.path.join(outputFolder, outputFilename)
  # print("outputFullPath=%s" % outputFullPath)

  print("Exporting result to file ...")
  print("  folder: %s" % outputFolder)
  print("  file: %s" % outputFilename)
  saveJsonToFile(outputFullPath, resultDict)
  print("Exported: %s" % outputFullPath)
