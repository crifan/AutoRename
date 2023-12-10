# AutoRename

IDA plugin for auto rename symbol

## Git Repo

https://github.com/crifan/AutoRename

https://github.com/crifan/AutoRename.git

## Background

when iOS reverse, using IDA pseudocode to anlysis function logic, but too many `sub_XXX` default name functions.

while many of them are simple function:

* only few instructions
* and match simple logic
  * for exmaple
    * all `MOV` then end with `RET`
    * all `MOV` then end with `B`
    * all `STP` then end with `RET` = I called it `prologue` function
    * ....

previsouly, need manual to rename to reflect it content, such as

```bash
__text:00000001023A2534 sub_1023A2534
__text:00000001023A2534                 MOV             X5, X0
__text:00000001023A2538                 MOV             X0, X19
__text:00000001023A253C                 RET
```

rename from `sub_1023A2534` to `X0toX5_X19toX0_2534`

here try use (IDA Plugin) python code to automate whole rename process, to facilitate iOS reverse

## Example

### AllMovThenRet

#### sub_10235F998 -> X24toX0_X23toX2_F998

```bash
__text:000000010235F998 X24toX0_X23toX2_F998
__text:000000010235F998                 MOV             X0, X24
__text:000000010235F99C                 MOV             X2, X23
__text:000000010235F9A0                 RET
```

#### sub_10235F980 -> `func_0toX3_0toX4_X20toX5_F980`

```bash
__text:000000010235F980 sub_10235F980
__text:000000010235F980                 MOV             X3, #0
__text:000000010235F984                 MOV             X4, #0
__text:000000010235F988                 MOV             X5, X20
__text:000000010235F98C                 RET
```

#### sub_10001CBA8 -> X20toX0_0x30toW1_0x7toW2_CBA8

```bash
__text:000000010001CBA8 sub_10001CBA8
__text:000000010001CBA8                 MOV             X0, X20
__text:000000010001CBAC                 MOV             W1, #0x30 ; '0'
__text:000000010001CBB0                 MOV             W2, #7
__text:000000010001CBB4                 RET
```

## TODO

* [ ] support `FMOV`
* [ ] support `prologue`
* [ ] support all `Functions`, `Names`
