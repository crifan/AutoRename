# Function: IDA script plugin, auto rename for all (Functions, Names) symbols
# Author: Crifan Li
# Update: 20231214

import re
import os
import json

import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
# import time
import codecs

import idc
import idaapi
import idautils
import ida_nalt
import ida_segment

################################################################################
# Config & Settings & Const
################################################################################

# verbose log
isVerbose = False
# isVerbose = True

# export result to json file
# isExportResult = False
isExportResult = True

if isExportResult:
  # outputFolder = None
  outputFolder = "/Users/crifan/dev/dev_root/crifan/github/AutoRename/debug"

SINGLE_INSTRUCTION_SIZE = 4 # bytes
# for rename, the max number of instruction to support
# MAX_INSTRUCTION_NUM = 6
MAX_INSTRUCTION_NUM = 8
MAX_INSTRUCTION_SIZE = MAX_INSTRUCTION_NUM * SINGLE_INSTRUCTION_SIZE

################################################################################
# Util Function
################################################################################

def logMain(mainStr):
  mainDelimiter = "="*40
  print("%s %s %s" % (mainDelimiter, mainStr, mainDelimiter))

def logSub(subStr):
  subDelimiter = "-"*30
  print("%s %s %s" % (subDelimiter, subStr, subDelimiter))

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
  addStr = None
  # subMatch = re.match("^sub_[0-9A-Za-z]+$", funcName)
  subMatch = re.match("^sub_(?P<addStr>[0-9A-Fa-f]+)$", funcName)
  # print("subMatch=%s" % subMatch)
  if subMatch:
    isSub = True
    addStr = subMatch.group("addStr")
  return isSub, addStr

def isReservedPrefix_loc(funcName):
  """
  check is reserved prefix loc_XXX name or not
  eg:
    loc_100007A2C -> True, "100007A2C"
  """
  isLoc = False
  addStr = None
  locMatch = re.match("^loc_(?P<addStr>[0-9A-Fa-f]+)$", funcName)
  # print("locMatch=%s" % locMatch)
  if locMatch:
    isLoc = True
    addStr = locMatch.group("addStr")
  return isLoc, addStr

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


  def __init__(self, operand, type, value):
    self.operand = operand
    self.type = type
    self.value = value

  def __str__(self):
    valStr = ""
    if self.value < 0:
      valStr = "%s" % self.value
    else:
      valStr = "0x%X" % self.value
    curOpStr = "<Operand: op=%s,type=%d,val=%s>" % (self.operand, self.type, valStr)
    # print("curOpStr=%s" % curOpStr)
    return curOpStr

  @staticmethod
  def listToStr(operandList):
    # operandStrList = []
    # for curOperand in operandList:
    #   curOperandStr = "%s" % curOperand
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

  def isValid(self):
    isValidOperand = bool(self.operand)
    isValidType = self.type != Operand.o_void
    isValidValue = self.value >= 0
    isValidAll = isValidOperand and isValidType and isValidValue
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
      if (self.immVal >= 0) and (self.immVal < 8):
        # contentStr = "0"
        contentStr = "%X" % self.immVal
      else:
        contentStr = self.immValHex
    # print("contentStr=%s" % contentStr)
    # TODO: add more case
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
    parsedInst = None

    instName = idc.print_insn_mnem(addr)
    # print("instName=%s" % instName)

    curOperandIdx = 0
    curOperandVaild = True
    operandList = []
    while curOperandVaild:
      # logSub("[%d]" % curOperandIdx)
      curOperand = idc.print_operand(addr, curOperandIdx)
      # print("curOperand=%s" % curOperand)
      curOperandType = idc.get_operand_type(addr, curOperandIdx)
      # print("curOperandType=%d" % curOperandType)
      curOperandValue = idc.get_operand_value(addr, curOperandIdx)
      # print("curOperandValue=%s=0x%X" % (curOperandValue, curOperandValue))
      curOperand = Operand(curOperand, curOperandType, curOperandValue)
      # print("curOperand=%s" % curOperand)
      if curOperand.isValid():
        operandList.append(curOperand)
      else:
        # print("End of operand for invalid %s" % curOperand)
        curOperandVaild = False

      # print("curOperandVaild=%s" % curOperandVaild)
      curOperandIdx += 1

    parsedInst = Instruction(addr=addr, name=instName, operands=operandList)
    # print("parsedInst=%s" % parsedInst)
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
    if self.isMov() or self.isFmov():
      operandNum = len(self.operands)
      if operandNum == 2:
        srcOperand = self.operands[1]
        # print("srcOperand=%s" % srcOperand)
        srcOperandStr = srcOperand.contentStr
        # print("srcOperandStr=%s" % srcOperandStr)
        dstOperand = self.operands[0]
        # print("dstOperand=%s" % dstOperand)
        dstOperandStr = dstOperand.contentStr
        # print("dstOperandStr=%s" % dstOperandStr)
        contentStr = "%sto%s" % (srcOperandStr, dstOperandStr)

      # TODO: add case for operand > 2 

    # TODO: add other Instruction support: ADD/SUB/LDR/STR/...
    # print("contentStr=%s" % contentStr)
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

  def isSub(self):
    return self.isInst("SUB")

  def isStr(self):
    return self.isInst("STR")

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

def checkAllMovThenRet(instructionList):
  isAllMovThenRet = False

  lastInst = instructionList[-1]
  # print("lastInst=%s" % lastInst)
  lastIsRet = lastInst.isRet()
  # print("lastIsRet=%s" % lastIsRet)
  if lastIsRet:
    instListExceptLast = instructionList[:-1]
    # print("instListExceptLast=%s" % instListExceptLast)
    # print("instListExceptLast=%s" % Instruction.listToStr(instListExceptLast))
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

def isNeedProcessFunc(curFuncAddr):
  isNeedProcess = False
  isDefaultSubFunc, funcName = isDefaultSubFunction(curFuncAddr)
  if isDefaultSubFunc:
    curFuncSize = ida_getFunctionSize(curFuncAddr)
    # print("curFuncSize=%s" % curFuncSize)
    # if curFuncSize <= MAX_INSTRUCTION_SIZE:
    if isFuncSizeValid(curFuncSize):
      isNeedProcess = True
  
  return isNeedProcess

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
      # TODO: add support sub_XXX
      print("TODO: add support for jump to %s" % branchFunc)
      branchFunc = None
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
  # print("branchFunc=%s" % branchFunc)
  return branchFunc


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
# allFuncAddrList = toProcessFuncAddrList

# normal code
allFuncAddrList = ida_getFunctionAddrList()
allFuncAddrListNum = len(allFuncAddrList)
print("allFuncAddrListNum=%d" % allFuncAddrListNum)
toProcessFuncAddrList = []
for eachFuncAddr in allFuncAddrList:
  isNeedProcess = isNeedProcessFunc(eachFuncAddr)
  if isNeedProcess:
    toProcessFuncAddrList.append(eachFuncAddr)
    # print("+ [0x%X]" % eachFuncAddr)

toProcessFuncAddrListNum = len(toProcessFuncAddrList)
print("toProcessFuncAddrListNum=%d" % toProcessFuncAddrListNum)

toRenameNum = 0
renameOkNum = 0
renameFailNum = 0

if isExportResult:
  renameDict = {}
  renameOkList_allMovThenRet = []
  renameOkList_allMovThenBranch = []
  renameOkList_prologue = []
  renameFailList = []

for curNum, funcAddr in enumerate(toProcessFuncAddrList, start=1):
  funcAddrStr = "0x%X" % funcAddr
  logMain("[%08d/%08d] %s" % (curNum, toProcessFuncAddrListNum, funcAddrStr))

  funcName = ida_getFunctionName(funcAddr)
  funcSize = ida_getFunctionSize(funcAddr)
  if not isFuncSizeValid(funcSize):
    print("Omit [%s] for invalid function size %d" % (funcAddrStr, funcSize))
    continue

  funcEndAddr = ida_getFunctionEndAddr(funcAddr)

  if isVerbose:
    print("funcName=%s, funcSize=%d=0x%X, funcEndAddr=0x%X" % (funcName, funcSize, funcSize, funcEndAddr))

  isMatchSomePattern = False

  isAllMovThenRet = False
  isAllMovThenBranch = False
  isPrologue = False

  disAsmInstList = []
  for curFuncAddr in range(funcAddr, funcEndAddr, SINGLE_INSTRUCTION_SIZE):
    # if isVerbose:
    #   logSub("[0x%X]" % curFuncAddr)
    newInst = Instruction.parse(curFuncAddr)
    # if isVerbose:
    #   print("newInst=%s" % newInst)
    disAsmInstList.append(newInst)

  if isVerbose:
    instDisasmStrList = Instruction.listToStr(disAsmInstList)
    print("instDisasmStrList=%s" % instDisasmStrList)

  if not isMatchSomePattern:
    isAllMovThenRet = checkAllMovThenRet(disAsmInstList)
    if isVerbose:
      print("isAllMovThenRet=%s" % isAllMovThenRet)
    if isAllMovThenRet:
      isMatchSomePattern = True

  if not isMatchSomePattern:
    isAllMovThenBranch = checkAllMovThenBranch(disAsmInstList)
    if isVerbose:
      print("isAllMovThenBranch=%s" % isAllMovThenBranch)
    if isAllMovThenBranch:
      isMatchSomePattern = True

  funcNamePrevPart = None
  newFuncName = None
  retryFuncName = None

  # print("isMatchSomePattern=%s" % isMatchSomePattern)
  if isMatchSomePattern:
    instListExceptLast = disAsmInstList[0:-1]
    # print("instListExceptLast=%s" % instListExceptLast)

    if isAllMovThenRet:
      prevPartContentStr = generateInstContentListStr(instListExceptLast)
      # print("prevPartContentStr=%s" % prevPartContentStr)
      funcNamePrevPart = prevPartContentStr

    if isAllMovThenBranch:
      prevPartContentStr = generateInstContentListStr(instListExceptLast, isFirstDigitAddPrefix=False)
      # print("prevPartContentStr=%s" % prevPartContentStr)

      branchInst = disAsmInstList[-1]
      # print("branchInst=%s" % branchInst)

      branchName = generateBranchName(branchInst)
      # print("branchInst=%s" % branchInst)

      if branchName:
        funcNamePrevPart = "%s_%s" % (branchName, prevPartContentStr)

    # print("funcNamePrevPart=%s" % funcNamePrevPart)
    if funcNamePrevPart:
      funcAllAddrStr = "%X" % funcAddr
      # print("funcAllAddrStr=%s" % funcAllAddrStr)
      addrLast4Str = funcAllAddrStr[-4:]
      # print("addrLast4Str=%s" % addrLast4Str)

      newFuncName = "%s_%s" % (funcNamePrevPart, addrLast4Str)
      retryFuncName = "%s_%s" % (funcNamePrevPart, funcAllAddrStr)
      # print("newFuncName=%s, retryFuncName=%s" % (newFuncName, retryFuncName))
    else:
      newFuncName = None
      retryFuncName = None

    # # for debug
    # print("Test to rename: [0x%X] %s, %s" % (funcAddr, newFuncName, retryFuncName))

    if newFuncName:
      toRenameNum += 1
      isRenameOk, renamedName = ida_rename(funcAddr, newFuncName, retryFuncName)
      if isVerbose:
        print("isRenameOk=%s, renamedName=%s" % (isRenameOk, renamedName))
      if isRenameOk:
        renameOkNum += 1
        print("renamed: [0x%X] %s -> %s" % (funcAddr, funcName, renamedName))
        if isExportResult:
          reamedOkItemDict = {
              "address": funcAddrStr,
              "oldName": funcName,
              "newName": renamedName,
            }

          if isAllMovThenRet:
            renameOkList_allMovThenRet.append(reamedOkItemDict)
          
          if isAllMovThenBranch:
            renameOkList_allMovThenBranch.append(reamedOkItemDict)

          if isPrologue:
            renameOkList_prologue.append(reamedOkItemDict)
      else:
        print("! rename fail for [0x%X] %s -> %s or %s" % (funcAddr, funcName, renamedName, retryFuncName))
        renameFailNum += 1
        if isExportResult:
          renameFailDict = {
            "address": funcAddrStr,
            "oldName": funcName,
            "newName": newFuncName,
            "retryName": retryFuncName,
          }
          renameFailList.append(renameFailDict)

logMain("Summary Info")
print("Total Functions num: %d" % len(allFuncAddrList))
print("To process function num: %d" % toProcessFuncAddrListNum)
print("To rename function num: %d" % toRenameNum)
print("  OK num: %d" % renameOkNum)
print("    allMovThenRet: %d" % len(renameOkList_allMovThenRet))
print("    allMovThenBranch: %d" % len(renameOkList_allMovThenBranch))
print("    prologue: %d" % len(renameOkList_prologue))
print("  fail num: %d" % renameFailNum)

if isExportResult:
  logMain("Export result to file")

  renameDict = {
    "ok": {
      "allMovThenRet": renameOkList_allMovThenRet,
      "allMovThenBranch": renameOkList_allMovThenBranch,
      "prologue": renameOkList_prologue,
    },
    "fail": renameFailList,
  }

  # outputFilename = "IDA_renamedResult_%s.json" % curDateTimeStr
  outputFilename = "%s_IdaRenamedResult_%s.json" % (curBinFilename, curDateTimeStr)
  # print("outputFilename=%s" % outputFilename)
  outputFullPath = os.path.join(outputFolder, outputFilename)
  # print("outputFullPath=%s" % outputFullPath)

  print("Exporting result to file ...")
  print("  folder: %s" % outputFolder)
  print("  file: %s" % outputFilename)
  saveJsonToFile(outputFullPath, renameDict)
  print("Exported: %s" % outputFullPath)
