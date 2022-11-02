# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
import dataclasses
from enum import Enum
from typing import List, Optional, Union

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
from saleae.data import SaleaeTime


@dataclasses.dataclass(frozen=True)
class Byte:
    value: int
    start_time: SaleaeTime
    end_time: SaleaeTime


@dataclasses.dataclass(frozen=True)
class CommandDescription:
    id: int
    name: str
    argument_names: Optional[List[str]] = None
    response_names: Optional[List[str]] = None


class Command(Enum):
    POWER_UP = 0x02
    NOP = 0x00
    PART_INFO = 0x01
    FUNC_INFO = 0x10
    SET_PROPERTY = 0x11
    GET_PROPERTY = 0x12
    GPIO_PIN_CFG = 0x13
    FIFO_INFO = 0x15
    GET_INT_STATUS = 0x20
    REQUEST_DEVICE_STATE = 0x33
    CHANGE_STATE = 0x34
    OFFLINE_RECAL = 0x38
    READ_CMD_BUFF = 0x44
    FRR_A_READ = 0x50
    FRR_B_READ = 0x51
    FRR_C_READ = 0x53
    FRR_D_READ = 0x57
    IRCAL_MANUAL = 0x1a
    TX_HOP = 0x37
    WRITE_TX_FIFO = 0x66
    PACKET_INFO = 0x16
    GET_MODEM_STATUS = 0x22
    START_RX = 0x32
    RX_HOP = 0x36
    READ_RX_FIFO = 0x77
    GET_ADC_READING = 0x14
    GET_PH_STATUS = 0x21
    GET_CHIP_STATUS = 0x23


# @formatter:off
COMMAND_LIST = [
    CommandDescription(0x02, "POWER_UP",
                       ["CMD", "BOOT_OPTIONS", "XTAL_OPTIONS", "XO_FREQ[31:24]", "XO_FREQ[23:16]", "XO_FREQ[15:8]", "XO_FREQ[7:0]"],
                       ["CTS"]),
    CommandDescription(0x00, "NOP",
                       ["CMD"],
                       ["CTS"]),
    CommandDescription(0x01, "PART_INFO",
                       ["CMD"],
                       ["CTS", "CHIPREV", "PART[15:8]", "PART[7:0]", "PBUILD", "ID[15:8]", "ID[7:0]", "CUSTOMER", "ROMID"]),
    CommandDescription(0x10, "FUNC_INFO",
                       ["CMD"],
                       ["CTS", "REVEXT", "REVBRANCH", "REVINT", "PATCH[15:8]", "PATCH[7:0]", "FUNC"]),
    CommandDescription(0x11, "SET_PROPERTY",
                       ["CMD", "GROUP", "NUM_PROPS", "START_PROP"] + [f"DATA[{x}]" for x in range(0, 12)],
                       ["CTS"]),
    CommandDescription(0x12, "GET_PROPERTY",
                       ["CMD", "GROUP", "NUM_PROPS", "START_PROP"],
                       ["CTS"] + [f"DATA[{x}]" for x in range(0, 16)]),
    CommandDescription(0x13, "GPIO_PIN_CFG",
                       ["CMD", "GPIO[0]", "GPIO[1]", "GPIO[2]", "GPIO[3]", "NIRQ", "SDO", "GEN_CONFIG"],
                       ["CTS", "GPIO[0]", "GPIO[1]", "GPIO[2]", "GPIO[3]", "NIRQ", "SDO", "GEN_CONFIG"]),
    CommandDescription(0x15, "FIFO_INFO",
                       ["CMD", "FIFO"],
                       ["CTS", "RX_FIFO_COUNT", "TX_FIFO_SPACE"]),
    CommandDescription(0x20, "GET_INT_STATUS",
                       ["CMD", "PH_CLR_PEND", "MODEM_CLR_PEND", "CHIP_CLR_PEND"],
                       ["CTS", "INT_PEND", "INT_STATUS", "PH_PEND", "PH_STATUS", "MODEM_PEND", "MODEM_STATUS", "CHIP_PEND", "CHIP_STATUS", "INFO_FLAGS"]),
    CommandDescription(0x33, "REQUEST_DEVICE_STATE",
                       ["CMD"],
                       ["CTS", "CURR_STATE", "CURRENT_CHANNEL"]),
    CommandDescription(0x34, "CHANGE_STATE",
                       ["CMD", "NEXT_STATE1"],
                       ["CTS"]),
    CommandDescription(0x38, "OFFLINE_RECAL",
                       ["CMD", "CAL_CTRL"],
                       ["CTS"]),
    CommandDescription(0x44, "READ_CMD_BUFF",
                       ["CMD"],
                       ["CTS"] + [f"BYTE[{x}]" for x in range(0, 16)]),
    CommandDescription(0x50, "FRR_A_READ",
                       ["CMD"],
                       ["CTS", "FRR_A_VALUE", "FRR_B_VALUE", "FRR_C_VALUE", "FRR_D_VALUE"]),
    CommandDescription(0x51, "FRR_B_READ",
                       ["CMD"],
                       ["CTS", "FRR_B_VALUE", "FRR_C_VALUE", "FRR_D_VALUE", "FRR_A_VALUE"]),
    CommandDescription(0x53, "FRR_C_READ",
                       ["CMD"],
                       ["CTS", "FRR_C_VALUE", "FRR_D_VALUE", "FRR_A_VALUE", "FRR_B_VALUE"]),
    CommandDescription(0x57, "FRR_D_READ",
                       ["CMD"],
                       ["CTS", "FRR_D_VALUE", "FRR_A_VALUE", "FRR_B_VALUE", "FRR_C_VALUE", ]),
    CommandDescription(0x17, "IRCAL",
                       ["CMD", "SEARCHING_STEP_SIZE", "SEARCHING_RSSI_AVG", "RX_CHAIN_SETTING1", "RX_CHAIN_SETTING2"],
                       ["CTS"]),
    CommandDescription(0x1a, "IRCAL_MANUAL",
                       ["CMD", "IRCAL_AMP", "IRCAL_PH"],
                       ["CTS", "IRCAL_AMP_REPLY", "IRCAL_PH_REPLY"]),
    CommandDescription(0x31, "START_TX",
                       ["CMD", "CHANNEL", "CONDITION", "TX_LEN[12:8]", "TX_LEN[7:0]", "TX_DELAY", "NUM_REPEAT"],
                       ["CTS"]),
    CommandDescription(0x37, "TX_HOP",
                       ["CMD", "INTE", "FRAC[22:16]", "FRAC[15:8]", "FRAC[7:0]", "VCO_CNT[15:8]", "VCO_CNT[7:0]", "PLL_SETTLE_TIME[15:8]", "PLL_SETTLE_TIME[7:0]"],
                       ["CTS"]),
    CommandDescription(0x66, "WRITE_TX_FIFO"),
    CommandDescription(0x16, "PACKET_INFO",
                       ["CMD", "FIELD_NUMBER", "LEN[15:8]", "LEN[7:0]", "LEN_DIFF[15:8]", "LEN_DIFF[7:0]"],
                       ["CTS", "LENGTH[15:8]", "LENGTH[7:0]"]),
    CommandDescription(0x22, "GET_MODEM_STATUS",
                       ["CMD", "MODEM_CLR_PEND"],
                       ["CTS", "MODEM_PEND", "MODEM_STATUS", "CURR_RSSI", "LATCH_RSSI", "ANT1_RSSI", "ANT2_RSSI", "AFC_FREQ_OFFSET[15:8]", "AFC_FREQ_OFFSET[7:0]", "INFO_FLAGS"]),
    CommandDescription(0x32, "START_RX",
                       ["CMD", "CHANNEL", "CONDITION", "RX_LEN[12:8]", "RX_LEN[7:0]", "RXTIMEOUT_STATE", "RXVALID_STATE", "RXINVALID_STATE"],
                       ["CTS"]),
    CommandDescription(0x36, "RX_HOP",
                       ["CMD", "INTE", "FRAC[19:16]", "FRAC[15:8]", "FRAC[7:0]", "VCO_CNT[15:8]", "VCO_CNT[7:0]"],
                       ["CTS"]),
    CommandDescription(0x77, "READ_RX_FIFO", ["CMD"]),
    CommandDescription(0x14, "GET_ADC_READING",
                       ["CMD", "ADC_EN", "ADC_CFG"],
                       ["CTS", "GPIO_ADC[10:8]", "GPIO_ADC[7:0]", "BATTERY_ADC[10:8]", "BATTERY_ADC[7:0]", "TEMP_ADC[10:8]", "TEMP_ADC[7:0]"]),
    CommandDescription(0x21, "GET_PH_STATUS",
                       ["CMD", "PH_CLR_PEND"],
                       ["CTS", "PH_PEND", "PH_STATUS"]),
    CommandDescription(0x23, "GET_CHIP_STATUS",
                       ["CMD", "CHIP_CLR_PEND"],
                       ["CTS", "CHIP_PEND", "CHIP_STATUS", "CMD_ERR_STATUS", "CMD_ERR_CMD_ID", "INFO_FLAGS"]),
]
# @formatter:on

COMMAND_ID_TO_NAME = {cmd.id: cmd.name for cmd in COMMAND_LIST}
COMMAND_ID_TO_DESCRIPTION = {cmd.id: cmd for cmd in COMMAND_LIST}

# The following commands can read their response right after sending out the command byte:
COMMANDS_WITH_IMMEDIATE_RESPONSE = [Command.FRR_A_READ.value,
                                    Command.FRR_B_READ.value,
                                    Command.FRR_C_READ.value,
                                    Command.FRR_D_READ.value,
                                    Command.READ_CMD_BUFF.value,
                                    Command.READ_RX_FIFO.value]


def decode_immediate_reponse_byte(command_id: int, received: List[Byte]) -> AnalyzerFrame:
    """Interpret received data as response to the current command."""
    last_byte = received[-1]
    count = len(received)
    last_byte_offset = count - 1
    payload = f"0x{last_byte.value:02x}"
    name = "Unknown immediate response"
    assert command_id in COMMANDS_WITH_IMMEDIATE_RESPONSE

    if command_id == Command.READ_CMD_BUFF.value:
        if last_byte_offset == 0:
            name = "CTS"
        else:
            name = f"BYTE[{last_byte_offset - 1}]"
    elif command_id == Command.READ_RX_FIFO.value:
        name = f"DATA[{last_byte_offset}]"
    elif command_id == Command.FRR_A_READ.value:
        assert last_byte_offset <= 3
        if last_byte_offset == 0:
            name = "FRR_A_VALUE"
        elif last_byte_offset == 1:
            name = "FRR_B_VALUE"
        elif last_byte_offset == 2:
            name = "FRR_C_VALUE"
        elif last_byte_offset == 3:
            name = "FRR_D_VALUE"
    elif command_id == Command.FRR_B_READ.value:
        assert last_byte_offset <= 3
        if last_byte_offset == 0:
            name = "FRR_B_VALUE"
        elif last_byte_offset == 1:
            name = "FRR_C_VALUE"
        elif last_byte_offset == 2:
            name = "FRR_D_VALUE"
        elif last_byte_offset == 3:
            name = "FRR_A_VALUE"
    elif command_id == Command.FRR_C_READ.value:
        assert last_byte_offset <= 3
        if last_byte_offset == 0:
            name = "FRR_C_VALUE"
        elif last_byte_offset == 1:
            name = "FRR_D_VALUE"
        elif last_byte_offset == 2:
            name = "FRR_A_VALUE"
        elif last_byte_offset == 3:
            name = "FRR_B_VALUE"
    elif command_id == Command.FRR_D_READ.value:
        assert last_byte_offset <= 3
        if last_byte_offset == 0:
            name = "FRR_D_VALUE"
        elif last_byte_offset == 1:
            name = "FRR_A_VALUE"
        elif last_byte_offset == 2:
            name = "FRR_B_VALUE"
        elif last_byte_offset == 3:
            name = "FRR_C_VALUE"
    return AnalyzerFrame('command_payload', last_byte.start_time, last_byte.end_time, {
        'name': f"< {name}",
        'payload': payload
    })


def decode_read_cmd_buff_reponse_byte(previous_command_id: int, received: List[Byte]) -> AnalyzerFrame:
    """Interpret received data as response to the command issued previously."""
    last_byte = received[-1]
    count = len(received)
    last_byte_offset = count - 1
    payload = f"0x{last_byte.value:02x}"
    name = "Unexpected response"
    if count == 1:
        name = "CTS (ready)" if last_byte.value == 0xFF else "CTS (not ready)"
    else:
        try:
            if previous_command_id == Command.FIFO_INFO.value:
                if count == 2:
                    name = f"RX_FIFO_COUNT ({last_byte.value})" if last_byte.value <= 129 else "RX_FIFO_COUNT (overflow!)"
                elif count == 3:
                    name = f"TX_FIFO_SPACE ({last_byte.value})" if last_byte.value <= 129 else "TX_FIFO_SPACE (illegal!)"
            else:
                name = COMMAND_ID_TO_DESCRIPTION[previous_command_id].response_names[last_byte_offset]
        except:
            pass
    return AnalyzerFrame('command_payload', last_byte.start_time, last_byte.end_time, {
        'name': f"< {name}",
        'payload': payload
    })


def decode_argument_byte(command_id: int, sent: List[Byte]) -> AnalyzerFrame:
    """Interpret bytes set by a command."""
    assert command_id == sent[0].value
    # print("Sent: " + " ".join(f"0x{b.value:02x}" for b in sent))
    last_byte = sent[-1]
    count = len(sent)
    last_byte_offset = count - 1
    name = "Unknown argument",
    try:
        if command_id == Command.WRITE_TX_FIFO.value:
            name = f"DATA[{last_byte_offset}]"
        else:
            name = COMMAND_ID_TO_DESCRIPTION[command_id].argument_names[last_byte_offset]
    except:
        print(f"Command with ID 0x{command_id:02x} has no description for offset {last_byte_offset}")

    return AnalyzerFrame('command_payload', last_byte.start_time, last_byte.end_time, {
        'name': f"> {name}",
        'payload': f"0x{last_byte.value:02x}"
    })


class Si4467Analyzer(HighLevelAnalyzer):
    result_types = {
        'command': {
            'format': '{{data.name}}'
        },
        'command_payload': {
            'format': '{{data.name}} = {{data.payload}}'
        }
    }

    def __init__(self):
        self.nsel_start_time: Optional[SaleaeTime] = None
        self.current_command_id: Optional[int] = None
        self.previous_command_id: Optional[int] = None
        self._bytes_sent: List[Byte] = []
        self._bytes_received: List[Byte] = []

    def _add_frame_miso(self, frame: AnalyzerFrame) -> None:
        self._bytes_received.append(
            Byte(int(frame.data['miso'][0]), start_time=frame.start_time, end_time=frame.end_time))

    def _add_frame_mosi(self, frame: AnalyzerFrame) -> None:
        self._bytes_sent.append(Byte(int(frame.data['mosi'][0]), start_time=frame.start_time, end_time=frame.end_time))

    def decode(self, frame: AnalyzerFrame) -> Optional[Union[AnalyzerFrame, List[AnalyzerFrame]]]:
        if frame.type == 'enable':
            self.nsel_start_time = frame.start_time
            self.current_command_id = None
            self._bytes_sent: List[Byte] = []
            self._bytes_received: List[Byte] = []
            return

        if self.nsel_start_time is None:
            return

        if frame.type == 'disable':
            # NSEL might get pulled without any data exchange during startup
            if not self._bytes_sent:
                return

            first_byte = self._bytes_sent[0]
            result = AnalyzerFrame('command', self.nsel_start_time, frame.end_time, {
                'name': COMMAND_ID_TO_NAME[
                    first_byte.value] if first_byte.value in COMMAND_ID_TO_NAME else "Unknown command",
                'payload': " ".join(f"0x{b.value:02x}" for b in (self._bytes_sent + self._bytes_received))
            })
            self.nsel_start_time = None
            if self.current_command_id not in COMMANDS_WITH_IMMEDIATE_RESPONSE:
                self.previous_command_id = self.current_command_id
            self.current_command_id = None
            self._bytes_sent: List[Byte] = []
            self._bytes_received: List[Byte] = []
            return result

        if frame.type == 'result':
            # First byte is always command ID
            if self.current_command_id is None:
                assert len(self._bytes_sent) == 0
                assert len(self._bytes_received) == 0
                self._add_frame_mosi(frame)
                first_byte = self._bytes_sent[0]
                self.current_command_id = first_byte.value
                return AnalyzerFrame('command_payload', first_byte.start_time, first_byte.end_time, {
                    'name': "> CMD",
                    'payload': f"0x{first_byte.value:02x}"
                })
            # Meaning of values read by READ_CMD_BUFF depends on previous (probably missed) command
            if self.current_command_id == Command.READ_CMD_BUFF.value and self.previous_command_id:
                self._add_frame_miso(frame)
                return decode_read_cmd_buff_reponse_byte(self.previous_command_id, self._bytes_received)
            # Commands which read back values themselves (after their command ID)
            if self.current_command_id in COMMANDS_WITH_IMMEDIATE_RESPONSE:
                self._add_frame_miso(frame)
                return decode_immediate_reponse_byte(self.current_command_id, self._bytes_received)
            # Remaining commands just send out data, do not read back (respectively need READ_CMD_BUFF to do so)
            self._add_frame_mosi(frame)
            return decode_argument_byte(self.current_command_id, self._bytes_sent)
