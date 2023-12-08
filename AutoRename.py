# Function: IDA script plugin, auto rename for all (Functions, Names) symbols
# Author: Crifan Li
# Update: 20231208

import re
import json
import idc
import idaapi
# import idautils
# from idaapi import PluginForm
# import ida_nalt
# import ida_segment

################################################################################
# Config & Settings
################################################################################

# isVerbose = False
isVerbose = True

subDelimiter = "-"*30
mainDelimiter = "="*40

################################################################################
# Const
################################################################################

SINGLE_INSTRUCTION_SIZE = 4 # bytes

################################################################################
# Util Function
################################################################################

def ida_getFunctionEndAddr(funcAddr):
  """
  0x1023A2534 -> 0x1023A2540
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  return funcAddrEnd

def ida_getFunctionSize(funcAddr):
  """
  0x1023A2534 -> 12
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  funcAddStart = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_START)
  funcSize = funcAddrEnd - funcAddStart
  return funcSize

def ida_getFunctionName(funcAddr):
  """
  0x1023A2534 -> "sub_1023A2534"
  """
  funcName = idc.get_func_name(funcAddr)
  return funcName

def ida_getDissamLine(funcAddr):
  """
  0x1023A2534 -> "MOV             X5, X0"
  """
  # method 1: generate_disasm_line
  # disasmLine_forceCode = idc.generate_disasm_line(funcAddr, idc.GENDSM_FORCE_CODE)
  # print("disasmLine_forceCode: type=%s, val=%s" % (type(disasmLine_forceCode), disasmLine_forceCode))
  # disasmLine_multiLine = idc.generate_disasm_line(funcAddr, idc.GENDSM_MULTI_LINE)
  # print("disasmLine_multiLine: type=%s, val=%s" % (type(disasmLine_multiLine), disasmLine_multiLine))

  # method 2: GetDisasm
  disasmLine = idc.GetDisasm(funcAddr)
  # print("disasmLine: type=%s, val=%s" % (type(disasmLine), disasmLine))
  return disasmLine

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
      if 0 == self.immVal:
        contentStr = "0"
      else:
        contentStr = self.immValHex
    # print("contentStr=%s" % contentStr)
    # TODO: add more case
    return contentStr

  @property
  def regIdx(self):
    curRegIdx = None
    if self.isReg():
      # TODO: extract reg idx
      curRegIdx = 0
    return curRegIdx


# class Instruction(object):
class Instruction:
  def __init__(self, addr, name, operands):
    self.addr = addr
    self.name = name
    self.operands = operands
  
  def __str__(self):
    # operandsStrList = []
    # for curOperand in self.operands:
    #   curOperandStr = "%s" % curOperand
    #   # print("curOperandStr=%s" % curOperandStr)
    #   operandsStrList.append(curOperandStr)
    # operandsStrList = [str(eachOperand) for eachOperand in self.operands]
    # operandsAllStr = ", ".join(operandsStrList)
    # operandsAllStr = "[%s]" % operandsAllStr
    operandsAllStr = Operand.listToStr(self.operands)
    # print("operandsAllStr=%s" % operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,name=%s,operands=%s>" % (self.addr, self.name, self.operands)
    curInstStr = "<Instruction: addr=0x%X,name=%s,operands=%s>" % (self.addr, self.name, operandsAllStr)
    # print("curInstStr=%s" % curInstStr)
    return curInstStr

  @staticmethod
  def listToStr(instList):
    instStrList = [str(eachInst) for eachInst in instList]
    instListAllStr = ", ".join(instStrList)
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
      # print("%s [%d] %s" % (subDelimiter, curOperandIdx, subDelimiter))
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
    if not self.name:
      return False
    else:
      if (instName.lower() == self.name.lower()):
        return True
      else:
        return False   

  @property
  def contentStr(self):
    """
    convert to meaningful string of Instruction real action / content
    """
    contentStr = ""
    if self.isMov():
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

  def isRet(self):
    return self.isInst("RET")

  def isAdd(self):
    return self.isInst("ADD")

  def isSub(self):
    return self.isInst("SUB")

  def isStr(self):
    return self.isInst("STR")

  def isLdr(self):
    return self.isInst("LDR")

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

    isAllMov = True
    for eachInst in instListExceptLast:
      if not eachInst.isMov():
        isAllMov = False
        break
    # print("isAllMov=%s" % isAllMov)
    isAllMovThenRet = lastIsRet and isAllMov

  # print("isAllMovThenRet=%s" % isAllMovThenRet)
  return isAllMovThenRet


################################################################################
# Main
################################################################################

idaVersion = idaapi.IDA_SDK_VERSION
print("IDA Version: %s" % idaVersion)

# funcAddrList = [0x10235F980, 0x1023A2534, 0x1023A255C, 0x10235F998]
funcAddrList = [0x1023A2578]
for funcAddr in funcAddrList:
  print("%s [0x%X] %s" % (mainDelimiter, funcAddr, mainDelimiter))
  # # funcAddr = 0x1023A2534
  # funcAddr = 0x1023A255C
  # print("funcAddr=0x%X" % funcAddr)

  # insMnem = idc.print_insn_mnem(funcAddr)
  # print("insMnem: type=%s, val=%s" % (type(insMnem), insMnem))

  # # operandIdxList = [0, 1]
  # operandIdxList = [0, 1, 2]
  # for eachOperandIdx in operandIdxList:
  #   print("%s [%d] %s" % (subDelimiter, eachOperandIdx, subDelimiter))
  #   curOperand = idc.print_operand(funcAddr, eachOperandIdx)
  #   print("curOperand: type=%s, val=%s" % (type(curOperand), curOperand))
  #   curOperandType = idc.get_operand_type(funcAddr, eachOperandIdx)
  #   print("curOperandType: type=%s, val=%s" % (type(curOperandType), curOperandType))
  #   curOperandValue = idc.get_operand_value(funcAddr, eachOperandIdx)
  #   print("curOperandValue: type=%s, val=%s" % (type(curOperandValue), curOperandValue))


  funcName = ida_getFunctionName(funcAddr)
  print("funcName=%s" % funcName)

  funcSize = ida_getFunctionSize(funcAddr)
  print("funcSize: %d = 0x%X" % (funcSize, funcSize))

  funcEndAddr = ida_getFunctionEndAddr(funcAddr)
  print("funcEndAddr=0x%X" % funcEndAddr)

  isAllMovThenRet = False

  disAsmInstList = []

  # for curFuncAddr in range(funcAddr, funcEndAddr, SINGLE_INSTRUCTION_SIZE):
  #   print("%s [0x%X] %s" % (subDelimiter, curFuncAddr, subDelimiter))

  #   curDisasmLineStr = ida_getDissamLine(curFuncAddr)
  #   print("curDisasmLineStr=%s" % curDisasmLineStr)
  #   # MOV             X5, X0
  #   # MOV             X0, X19
  #   # MOV             X4, X21
  #   # MOV             W2, #3
  #   # MOV             X5, X23
  #   # RET

  #   # temp only support MOV Xd, Xn
  #   # TODO: add more instruction support

  #   isMovInst = False
  #   regSrc = None
  #   regDst = None
  #   isRetInst = False

  #   movInstMatch = re.search("MOV\s+(?P<regDst>X\d+)\s*,\s*(?P<regSrc>X\d+)", curDisasmLineStr, flags=re.I)
  #   print("movInstMatch=%s" % movInstMatch)
  #   if movInstMatch:
  #     isMovInst = True
  #     regSrc = movInstMatch.group("regSrc")
  #     regDst = movInstMatch.group("regDst")
  #   print("isMovInst=%s" % isMovInst)
  #   print("regSrc=%s, regDst=%s" % (regSrc, regDst))

  #   retInstMatch = re.search("RET", curDisasmLineStr, flags=re.I)
  #   print("retInstMatch=%s" % retInstMatch)
  #   if retInstMatch:
  #     isRetInst = True
  #   print("isRetInst=%s" % isRetInst)

  #   curDisAsmDict = {
  #     "disasm": curDisasmLineStr,
  #     "mov": {
  #       "isMov": isMovInst,
  #       "regSrc": regSrc,
  #       "regDst": regDst,
  #     },
  #     "ret": {
  #       "isRet": isRetInst,
  #     }
  #   }
  #   print("curDisAsmDict=%s" % curDisAsmDict)
  #   disAsmInstList.append(curDisAsmDict)

  # print("disAsmInstList=%s" % disAsmInstList)

  for curFuncAddr in range(funcAddr, funcEndAddr, SINGLE_INSTRUCTION_SIZE):
    print("%s [0x%X] %s" % (subDelimiter, curFuncAddr, subDelimiter))
    newInst = Instruction.parse(curFuncAddr)
    # print("newInst=%s" % newInst)
    disAsmInstList.append(newInst)

  isAllMovThenRet = checkAllMovThenRet(disAsmInstList)
  print("isAllMovThenRet=%s" % isAllMovThenRet)
  if isAllMovThenRet:
    instListExceptLast = disAsmInstList[0:-1]
    instStrList = []
    for eachInst in instListExceptLast:
      eachInstStr = eachInst.contentStr
      # print("eachInstStr=%s" % eachInstStr)
      instStrList.append(eachInstStr)

    funcAddrHexStr = "0x%X" % funcAddr
    # print("funcAddrHexStr=%s" % funcAddrHexStr)
    addrLast4Str = funcAddrHexStr[-4:]
    # print("addrLast4Str=%s" % addrLast4Str)

    funcAllInstStr = "_".join(instStrList)
    # print("funcAllInstStr=%s" % funcAllInstStr)

    newFuncName = "%s_%s" % (funcAllInstStr, addrLast4Str)
    # print("newFuncName=%s" % newFuncName)

    isFisrtIsDigit = re.match("^\d+", funcAllInstStr)
    # print("isFisrtIsDigit=%s" % isFisrtIsDigit)
    if isFisrtIsDigit:
      newFuncName = "func_%s" % newFuncName
    print("newFuncName=%s" % newFuncName)

    isRenameOk = idc.set_name(funcAddr, newFuncName)
    print("isRenameOk=%s" % isRenameOk)
    if isRenameOk == 1:
      resultStr = "ok"
    else:
      resultStr = "fail"
    print("rename %s: [0x%X] %s -> %s" % (resultStr, funcAddr, funcName, newFuncName))
  else:
    print("Unsupport [0x%X] %s" % (funcAddr, Instruction.listToStr(disAsmInstList)))
