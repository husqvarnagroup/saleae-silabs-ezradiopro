# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
import dataclasses
from typing import List, Optional

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
from saleae.data import SaleaeTime


# No CTS in reply stream:
# - FRR_A_READ
# - FRR_B_READ
# - FRR_C_READ
# - FRR_D_READ
# - READ_RX_FIFO

# No reply stream:
# - WRITE_TX_FIFO


@dataclasses.dataclass(frozen=True)
class Byte:
    value: int
    start_time: SaleaeTime
    end_time: SaleaeTime


@dataclasses.dataclass(frozen=True)
class CommandDescription:
    id: int
    name: str
    argument_names: List[str]
    reply_after: Optional[int] = None  # After how many bytes written will the Si4467 clocking out its answer?


COMMANDS_LIST = [
    CommandDescription(0x02, "POWER_UP",
                       ["CMD", "BOOT_OPTIONS", "XTAL_OPTIONS", "XO_FREQ[31:24]", "XO_FREQ[23:16]", "XO_FREQ[15:8]",
                        "XO_FREQ[7:0]"], 0),
    CommandDescription(0x00, "NOP", ["CMD"], 0),
    CommandDescription(0x01, "PART_INFO",
                       ["CMD", "CHIPREV", "PART[15:8]", "PART[7:0]", "PBUILD", "ID[15:8]", "ID[7:0]", "CUSTOMER",
                        "ROMID"], 0),
    CommandDescription(0x10, "FUNC_INFO", ["CMD", "REVEXT", "REVBRANCH", "REVINT", "PATCH[15:8]", "PATCH[7:0]", "FUNC"],
                       0),
    CommandDescription(0x11, "SET_PROPERTY",
                       ["CMD", "GROUP", "NUM_PROPS", "START_PROP", "DATA[0]", "DATA[1]", "DATA[2]", "DATA[3]",
                        "DATA[4]", "DATA[5]", "DATA[6]", "DATA[7]", "DATA[8]", "DATA[9]", "DATA[10]", "DATA[11]"], 0),
    CommandDescription(0x12, "GET_PROPERTY", ["CMD", "GROUP", "NUM_PROPS", "START_PROP"], 0),
    CommandDescription(0x13, "GPIO_PIN_CFG",
                       ["CMD", "GPIO[0]", "GPIO[1]", "GPIO[2]", "GPIO[3]", "NIRQ", "SDO", "GEN_CONFIG"], 0),
    CommandDescription(0x15, "FIFO_INFO", ["CMD", "FIFO"], 0),
    CommandDescription(0x20, "GET_INT_STATUS", ["CMD", "PH_CLR_PEND", "MODEM_CLR_PEND", "CHIP_CLR_PEND"], 0),
    CommandDescription(0x33, "REQUEST_DEVICE_STATE", ["CMD"], 0),
    CommandDescription(0x34, "CHANGE_STATE", ["CMD", "NEXT_STATE1"], 0),
    CommandDescription(0x38, "OFFLINE_RECAL", ["CMD", "CAL_CTRL"], 0),
    CommandDescription(0x44, "READ_CMD_BUFF", ["CMD"], 1),
    CommandDescription(0x50, "FRR_A_READ", ["CMD"], 1),
    CommandDescription(0x51, "FRR_B_READ", ["CMD"], 1),
    CommandDescription(0x53, "FRR_C_READ", ["CMD"], 1),
    CommandDescription(0x57, "FRR_D_READ", ["CMD"], 1),
    CommandDescription(0x1a, "IRCAL_MANUAL", ["CMD", "IRCAL_AMP", "IRCAL_PH"], 0),
    CommandDescription(0x31, "START_TX",
                       ["CMD", "CHANNEL", "CONDITION", "TX_LEN[12:8]", "TX_LEN[7:0]", "TX_DELAY", "NUM_REPEAT"], 0),
    CommandDescription(0x37, "TX_HOP",
                       ["CMD", "INTE", "FRAC[22:16]", "FRAC[15:8]", "FRAC[7:0]", "VCO_CNT[15:8]", "VCO_CNT[7:0]",
                        "PLL_SETTLE_TIME[15:8]", "PLL_SETTLE_TIME[7:0]"], 0),
    CommandDescription(0x66, "WRITE_TX_FIFO",
                       ["CMD", "data[0]", "data[1]", "data[2]", "data[3]", "data[4]", "data[5]", "data[6]", "data[7]",
                        "data[8]", "data[9]", "data[10]", "data[11]", "data[12]", "data[13]", "data[14]", "data[15]",
                        "data[16]", "data[17]", "data[18]", "data[19]", "data[20]", "data[21]", "data[22]", "data[23]",
                        "data[24]", "data[25]", "data[26]", "data[27]", "data[28]", "data[29]", "data[30]", "data[31]",
                        "data[32]", "data[33]", "data[34]", "data[35]", "data[36]", "data[37]", "data[38]", "data[39]",
                        "data[40]", "data[41]", "data[42]", "data[43]", "data[44]", "data[45]", "data[46]", "data[47]",
                        "data[48]", "data[49]", "data[50]", "data[51]", "data[52]", "data[53]", "data[54]", "data[55]",
                        "data[56]", "data[57]", "data[58]", "data[59]", "data[60]", "data[61]", "data[62]", "data[63]",
                        "data[64]", "data[65]", "data[66]", "data[67]", "data[68]", "data[69]", "data[70]", "data[71]",
                        "data[72]", "data[73]", "data[74]", "data[75]", "data[76]", "data[77]", "data[78]", "data[79]",
                        "data[80]", "data[81]", "data[82]", "data[83]", "data[84]", "data[85]", "data[86]", "data[87]",
                        "data[88]", "data[89]", "data[90]", "data[91]", "data[92]", "data[93]", "data[94]", "data[95]",
                        "data[96]", "data[97]", "data[98]", "data[99]", "data[100]", "data[101]", "data[102]",
                        "data[103]", "data[104]", "data[105]", "data[106]", "data[107]", "data[108]", "data[109]",
                        "data[110]", "data[111]", "data[112]", "data[113]", "data[114]", "data[115]", "data[116]",
                        "data[117]", "data[118]", "data[119]", "data[120]", "data[121]", "data[122]", "data[123]",
                        "data[124]", "data[125]", "data[126]", "data[127]", "data[128]", "data[129]"], 0),
    CommandDescription(0x16, "PACKET_INFO",
                       ["CMD", "FIELD_NUMBER", "LEN[15:8]", "LEN[7:0]", "LEN_DIFF[15:8]", "LEN_DIFF[7:0]"], 0),
    CommandDescription(0x22, "GET_MODEM_STATUS", ["CMD", "MODEM_CLR_PEND"], 0),
    CommandDescription(0x32, "START_RX",
                       ["CMD", "CHANNEL", "CONDITION", "RX_LEN[12:8]", "RX_LEN[7:0]", "RXTIMEOUT_STATE",
                        "RXVALID_STATE", "RXINVALID_STATE"], 0),
    CommandDescription(0x36, "RX_HOP",
                       ["CMD", "INTE", "FRAC[19:16]", "FRAC[15:8]", "FRAC[7:0]", "VCO_CNT[15:8]", "VCO_CNT[7:0]"], 0),
    CommandDescription(0x77, "READ_RX_FIFO", ["CMD"], 0),
    CommandDescription(0x14, "GET_ADC_READING", ["CMD", "ADC_EN", "ADC_CFG"], 0),
    CommandDescription(0x21, "GET_PH_STATUS", ["CMD", "PH_CLR_PEND"], 0),
    CommandDescription(0x23, "GET_CHIP_STATUS", ["CMD", "CHIP_CLR_PEND"], 0),
]

COMMANDS_MAP = {command.id: command for command in COMMANDS_LIST}


class Command:
    def __init__(self, start_time: SaleaeTime):
        self.description: Optional[CommandDescription] = None
        self.bytes: List[Byte] = []
        self.start_time = start_time

    def add_frame(self, frame: AnalyzerFrame):
        if self.description and len(self.bytes) < self.description.reply_after:
            direction = 'mosi'
        else:
            direction = 'miso'
        self.bytes.append(
            Byte(value=int(frame.data[direction][0]), start_time=frame.start_time, end_time=frame.end_time))

        if len(self.bytes) == 1:
            print(f"self.bytes[0].value={self.bytes[0].value}")
            try:
                self.description = COMMANDS_MAP[self.bytes[0].value]
            except KeyError:
                self.description = CommandDescription(self.bytes[0].value, "Unknown", [], 0)

    def get_result(self, end_time: SaleaeTime) -> List[AnalyzerFrame]:
        if not self.description:
            return
        result = [AnalyzerFrame('command', self.start_time, end_time, {
            'command_name': self.description.name,
            'payload': " ".join(f"0x{x.value:02x}" for x in self.bytes)
        })]

        for offset, name in enumerate(self.bytes):
            byte = self.bytes[offset]
            result.append(AnalyzerFrame('command_argument', byte.start_time, byte.end_time, {
                'name': self.description.argument_names[offset] if offset < len(
                    self.description.argument_names) else "Unknown argument",
                'payload': f"0x{byte.value:02x}"
            }))

        return result


class Si4467Analyzer(HighLevelAnalyzer):
    result_types = {
        'command': {
            'format': '{{data.command_name}}'
        }
    }

    def __init__(self):
        self.current_command: Optional[Command] = None

    def decode(self, frame: AnalyzerFrame):
        print(f"frame.type={frame.type}")
        if frame.type == 'enable':
            self.current_command = Command(frame.start_time)
            return

        if self.current_command is None:
            return

        if frame.type == 'disable':
            result = None
            try:
                result = self.current_command.get_result(frame.end_time)
                self.current_command = None
            except TypeError:
                return
            return result

        if frame.type == 'result':
            self.current_command.add_frame(frame)
            return
