import re
import sys
import os
import xlwt
import xlrd
from xlutils.copy import copy
import ntpath
import socket
import itertools
import struct
import argparse
import string
from datetime import date, datetime


def checkConfig(path):
    return_dict = {}
    file_handler = xlrd.open_workbook(path)
    sheet = file_handler.sheet_by_index(0)

    for row_index in range(0, sheet.nrows):
        if sheet.cell(row_index, 0).value == 'Decoding canalyser frames':
            network_list = dict()
            trace_col = -1
            NMoE_col = -1
            network_type = -1
            for col_index in range(0, sheet.ncols):
                if sheet.cell(row_index + 1, col_index).value == 'trace-bus-name':
                    trace_col = col_index
                if sheet.cell(row_index + 1, col_index).value == 'network-type':
                    network_type = col_index
                if sheet.cell(row_index + 1, col_index).value == 'NMoE-bus-Name':
                    NMoE_col = col_index
            if trace_col != -1 and NMoE_col != -1 and network_type != -1:
                for index in range(row_index + 2, sheet.nrows):
                    if sheet.cell(index, trace_col).value != "":
                        values = {}
                        try:
                            value = int(sheet.cell(index, trace_col).value)
                            name = str(value)
                        except:
                            value = sheet.cell(index, trace_col).value
                            name = value
                        values['NMoE-bus-name'] = sheet.cell(index, NMoE_col).value
                        values['network-type'] = sheet.cell(index, network_type).value
                        network_list[name] = values
                    else:
                        break

        if sheet.cell(row_index, 0).value == 'Criteria to analyse Ethernet files':
            return_dict['SOURCE-IP'] = sheet.cell(row_index+1, 1).value
            return_dict['DESTINATION-IP'] = sheet.cell(row_index + 2, 1).value
            return_dict['SOURCE-UDP'] = sheet.cell(row_index + 3, 1).value
            return_dict['DESTINATION-UDP'] = sheet.cell(row_index + 4, 1).value
            return_dict['SEQUENCE-NUMBER'] = sheet.cell(row_index + 5, 1).value
        if sheet.cell(row_index, 0).value == 'Offset data for calculation of bus and frame':
            return_dict['BUS'] = sheet.cell(row_index + 1, 1).value
            return_dict['FRAME'] = sheet.cell(row_index + 2, 1).value
        if sheet.cell(row_index, 0).value == 'Comparison color':
            return_dict['LOWER'] = sheet.cell(row_index + 1, 1).value
            return_dict['MIDDLE'] = sheet.cell(row_index + 2, 1).value
            return_dict['GREATER'] = sheet.cell(row_index + 3, 1).value

    return return_dict, network_list


def readFile(path):
    file = open(path, 'r')
    return_list = []
    for line in file:
        return_list.append(line.strip())
    return return_list


def filterData(content):
    return_list = []
    reg = re.compile("^\d*[.]?\d*$")
    for line in content:
        timestamp = line.split()[0]
        if reg.match(timestamp):
            return_list.append(line)
    return return_list


def sortData(content, network_list):
    lin_messages = []
    can_messages = []
    eth_messages = []
    for line in content:
        line_splited = line.split(" ")
        if line_splited[1] in network_list:
            if network_list[line_splited[1]]['network-type'] == 'LIN':
                lin_messages.append(line)
            elif network_list[line_splited[1]]['network-type'] == 'CAN':
                can_messages.append(line)
        else:
            if line_splited[1] == 'ETH':
                eth_messages.append(line)

    return lin_messages, can_messages, eth_messages


def checkEthernet(message_list, configuration):
    parsed_list = []
    data_list_total = []
    for message in message_list[:]:
        if " Rx " not in message and " Tx " not in message:
            message_list.remove(message)

    for message in message_list:
        dict_eth = {}
        message = message.split()
        dict_eth['TIMESTAMP'] = message[0]
        dict_eth['NETWORK'] = message[1]
        dict_eth['SEQNUMBER'] = message[2]
        dict_eth['DIRECTION'] = message[3]
        dict_eth['DATA'] = message[4]
        parsed_list.append(dict_eth)

    for message in parsed_list:
        decoded_data = decode(message['DATA'])
        source_ip = socket.inet_ntoa(struct.pack("!L", int(decoded_data["IP_SOURCE"], 16)))
        dest_ip = socket.inet_ntoa(struct.pack("!L", int(decoded_data["IP_DESTINATION"], 16)))
        source_udp = int(decoded_data['UDP_SOURCE'], 16)
        dest_udp = int(decoded_data['UDP_DESTINATION'], 16)
        seq_number = int(decoded_data['HEADER_SEQUENCE'], 16)
        if source_ip == configuration['SOURCE-IP'] and dest_ip == configuration['DESTINATION-IP'] and source_udp == int(configuration['SOURCE-UDP']) and dest_udp == int(configuration['DESTINATION-UDP']) and seq_number >= int(configuration['SEQUENCE-NUMBER']):
            data_list = []
            rank = 57
            n = 2
            frame_number = 1
            payload = [decoded_data['PAYLOAD'][i:i+n] for i in range(0, len(decoded_data['PAYLOAD']), n)]
            while True:
                payload_dict = {}
                index = 0
                payload_dict['RANK'] = rank
                payload_dict['SEQUENCE-NUMBER'] = seq_number
                payload_dict['FRAME-NUMBER'] = frame_number
                payload_dict['TIMESTAMP'] = message['TIMESTAMP']
                payload_dict['ETH-TIME'] = int(decoded_data['HEADER_TIMESTAMP'][:12], 16) + int(decoded_data['HEADER_TIMESTAMP'][12:], 16) / 1000000000
                payload_dict['TIME'] = str((int(payload[index] + payload[index + 1], 16)) * 0.00001)
                index = index + 2
                payload_dict['NETWORK-STATE-AVAILABILITY'] = '{0:08b}'.format((int(payload[index], 16)))[:1]
                payload_dict['FRAME-ID-AVAILABILITY'] = '{0:08b}'.format((int(payload[index], 16)))[1:2]
                payload_dict['PAYLOAD-AVAILABILITY'] = '{0:08b}'.format((int(payload[index], 16)))[2:3]
                payload_dict['NETWORK-TYPE'] = int('{0:08b}'.format((int(payload[index], 16)))[3:], 2)
                index = index + 1
                payload_dict['NETWORK-ID'] = payload[index]
                index = index + 1
                if payload_dict['NETWORK-STATE-AVAILABILITY'] == '1':
                    payload_dict['NETWORK-STATE'] = payload[index]
                    index = index + 1
                else:
                    payload_dict['NETWORK-STATE'] = None

                if payload_dict['FRAME-ID-AVAILABILITY'] == '1':
                    if payload_dict['NETWORK-TYPE'] == 1:
                        # treat CAN frames
                        payload_dict['FRAME-ID'] = int(payload[index + 1] + payload[index + 2] + payload[index + 3])
                        index = index + 4
                    elif payload_dict['NETWORK-TYPE'] == 2:
                        # treat LIN frames
                        payload_dict['FRAME-ID'] = payload[index]
                        index = index + 1
                else:
                    payload_dict['FRAME-ID'] = None

                if payload_dict['PAYLOAD-AVAILABILITY'] == '1':
                    payload_dict['LENGTH'] = int(payload[index], 16)
                    index = index + 1
                    payload_dict['DATA'] = "".join(payload[index:index + payload_dict['LENGTH']])
                    index = index + payload_dict['LENGTH']
                else:
                    payload_dict['LENGTH'] = None
                    payload_dict['DATA'] = None

                payload = payload[index:]
                if payload_dict['DATA'] is not None:
                    data_list.append(payload_dict)
                    frame_number = frame_number + 1
                rank = rank + index

                if not payload:
                    data_list = sorted(data_list, key=lambda x: x['TIME'])
                    data_list_total = data_list_total + data_list
                    break
    return data_list_total


def checkCan(message_list, network_list):
    return_list = []
    for message in message_list[:]:
        if "Error" in message:
            message_list.remove(message)
    for message in message_list:
        message = message.split()
        can_dict = {}
        can_dict['TIMESTAMP'] = float(message[0])
        if message[1] in network_list:
            can_dict['NETWORK'] = network_list[message[1]]['NMoE-bus-name']
        if all(c in string.hexdigits for c in message[2]):
            can_dict['ID'] = message[2]
        else:
            continue
        can_dict['DATA'] = ""
        for index in range(6, len(message)):
            if message[index] == "Length":
                break
            else:
                can_dict['DATA'] += message[index]
        return_list.append(can_dict)
    return return_list


def checkLin(message_list, network_list):
    return_list = []
    for message in message_list[:]:
        if "checksum" not in message:
            message_list.remove(message)
    for message in message_list:
        message = message.split()
        lin_dict = {}
        lin_dict['TIMESTAMP'] = float(message[0])
        if message[1] in network_list:
            lin_dict['NETWORK'] = network_list[message[1]]['NMoE-bus-name']
        lin_dict['ID'] = message[2]
        if all(c in string.hexdigits for c in message[5]):
            lin_dict['DATA'] = message[5]
            if all(c in string.hexdigits for c in message[6]):
                lin_dict['DATA'] = message[5] + message[6]
            else:
                pass
        else:
            continue
        return_list.append(lin_dict)
    return return_list


def decode(data):
    data = data.split(':')[-1]
    return_dict = {}
    return_dict['MAC_DESTINATION'] = data[:12]
    return_dict['MAC_SOURCE'] = data[12:24]
    return_dict['ETHERNET_TYPE'] = data[24:28]
    return_dict['IP_VERSION'] = data[28]
    return_dict['IP_HEADER_LENGTH'] = data[29]
    return_dict['IP_DS'] = data[30:32]
    return_dict['IP_LENGTH'] = data[32:36]
    return_dict['IP_IDENTIFICATION'] = data[36:40]
    return_dict['IP_OFFSET'] = data[40:44]
    return_dict['IP_TTL'] = data[44:46]
    return_dict['IP_PROTOCOL'] = data[46:48]
    return_dict['IP_CHECKSUM'] = data[48:52]
    return_dict['IP_SOURCE'] = data[52:60]
    return_dict['IP_DESTINATION'] = data[60:68]
    return_dict['UDP_SOURCE'] = data[68:72]
    return_dict['UDP_DESTINATION'] = data[72:76]
    return_dict['UDP_LENGTH'] = data[76:80]
    return_dict['UDP_CHECKSUM'] = data[80:84]
    return_dict['HEADER_PROTOCOL'] = data[84:86]
    return_dict['HEADER_SEQUENCE'] = data[86:88]
    return_dict['HEADER_TIMESTAMP'] = data[88:108]
    return_dict['HEADER_LENGTH'] = data[108:112]
    return_dict['PAYLOAD'] = data[112:]
    return return_dict


def get_sheet_by_name(book, name):
    """Get a sheet by name from xlwt.Workbook, a strangely missing method.
    Returns None if no sheet with the given name is present.
    """
    # Note, we have to use exceptions for flow control because the
    # xlwt API is broken and gives us no other choice.
    try:
        for idx in itertools.count():
            sheet = book.get_sheet(idx)
            if sheet.name == name:
                return sheet
    except IndexError:
        return None


def createFirstFile(path, tail, can_lin_data, eth_data):
    workbook = xlwt.Workbook()
    style_detail_information = xlwt.easyxf('align: wrap on, vert center, horiz center; border : bottom thin,right thin,top thin,left thin;')
    red_cell = xlwt.easyxf('align: wrap on, vert center, horiz center; pattern: pattern solid, fore_colour red; font: colour dark_red, bold False;')
    orange_cell = xlwt.easyxf('align: wrap on, vert center, horiz center; pattern: pattern solid, fore_colour yellow; font: colour orange, bold False;')
    green_cell = xlwt.easyxf('align: wrap on, vert center, horiz center; pattern: pattern solid, fore_colour light_green; font: colour green, bold False;')
    normal_cell = xlwt.easyxf('align: wrap on, vert center, horiz center;')
    # create and fill first sheet
    sheetInformation = workbook.add_sheet("INFORMATION", cell_overwrite_ok=True)
    sheetInformation.col(0).width = 256 * 30
    sheetInformation.col(1).width = 256 * 35
    sheetInformation.write(2, 0, ".asc file name", style_detail_information)
    sheetInformation.write(2, 1, tail, style_detail_information)
    sheetInformation.write(3, 0, "Tool execution date", style_detail_information)
    sheetInformation.write(3, 1, str(date.today()), style_detail_information)
    sheetInformation.write(4, 0, "Tool execution time", style_detail_information)
    sheetInformation.write(4, 1, str(datetime.now().strftime("%H:%M:%S")), style_detail_information)

    # create and fill CAN-LIN sheet
    sheetLogLinCan = workbook.add_sheet("LOG LIN CAN", cell_overwrite_ok=True)
    sheetLogLinCan.col(0).width = 256 * 15
    sheetLogLinCan.col(1).width = 256 * 15
    sheetLogLinCan.col(2).width = 256 * 15
    sheetLogLinCan.col(3).width = 256 * 25
    sheetLogLinCan.write(0, 0, "log time", normal_cell)
    sheetLogLinCan.write(0, 1, "NMoE bus name", normal_cell)
    sheetLogLinCan.write(0, 2, "log frameID", normal_cell)
    sheetLogLinCan.write(0, 3, "log data", normal_cell)
    index = 1
    for line in can_lin_data:
        sheetLogLinCan.write(index, 0, str(line['TIMESTAMP']).replace(".", ","), normal_cell)
        sheetLogLinCan.write(index, 1, line['NETWORK'], normal_cell)
        sheetLogLinCan.write(index, 2, line['ID'], normal_cell)
        sheetLogLinCan.write(index, 3, line['DATA'], normal_cell)
        index = index + 1

    #create and fill eth log sheet
    sheetEth = workbook.add_sheet("LOG ETH", cell_overwrite_ok=True)
    sheetEth.col(0).width = 256 * 15
    sheetEth.col(1).width = 256 * 15
    sheetEth.col(2).width = 256 * 15
    sheetEth.col(3).width = 256 * 15
    sheetEth.col(4).width = 256 * 15
    sheetEth.col(5).width = 256 * 15
    sheetEth.col(6).width = 256 * 15
    sheetEth.col(7).width = 256 * 15
    sheetEth.col(8).width = 256 * 15
    sheetEth.col(9).width = 256 * 15
    sheetEth.col(10).width = 256 * 15
    sheetEth.write(0, 0, "ETH_Sequence_Number", normal_cell)
    sheetEth.write(0, 1, "ETH_CAN-LIN_frame_number", normal_cell)
    sheetEth.write(0, 2, "ETH_CAN-LIN_frame_rank", normal_cell)
    sheetEth.write(0, 3, "ETH_CAN-LIN_Timestamp", normal_cell)
    sheetEth.write(0, 4, "ETH_Header-Time-Stamp", normal_cell)
    sheetEth.write(0, 5, "Calculated_CAN-LIN time", normal_cell)
    sheetEth.write(0, 6, "Connected-tool_offset", normal_cell)
    sheetEth.write(0, 7, "ETH_CAN-LIN_Time", normal_cell)
    sheetEth.write(0, 8, "NMoE_bus_name", normal_cell)
    sheetEth.write(0, 9, "ETH_CAN-LIN_FrameID", normal_cell)
    sheetEth.write(0, 10, "ETH_data", normal_cell)
    index = 1
    for line in eth_data:
        if line['DATA'] is not None:
            sheetEth.write(index, 0, line['SEQUENCE-NUMBER'], normal_cell)
            sheetEth.write(index, 1, line['FRAME-NUMBER'], normal_cell)
            sheetEth.write(index, 2, line['RANK'], normal_cell)
            sheetEth.write(index, 3, str(round(float(line['TIME']), 3)).replace(".", ","), normal_cell)
            sheetEth.write(index, 4, str(round(float(line['ETH-TIME']), 3)).replace(".", ","), normal_cell)
            sheetEth.write(index, 5, str(round(float(line['TIME']) + float(line['ETH-TIME']), 3)).replace(".", ","), normal_cell)
            sheetEth.write(index, 6, "0", normal_cell)
            # sheetEth.write(index, 6, xlwt.Formula("AVERAGE('OFFFSET DATA'!F:F)-AVERAGE('OFFSET DATA'!A:A)"), normal_cell)
            if line['NETWORK-TYPE'] == 1:
                network_type = 'CAN'
            elif line['NETWORK-TYPE'] == 2:
                network_type = 'LIN'
            elif line['NETWORK-TYPE'] == 3:
                network_type = 'Ethernet'
            else:
                network_type = 'INVALID'
            # sheetEth.write(index, 7, xlwt.Formula("G$2 + F" + str(index+1)), normal_cell)
            sheetEth.write(index, 7, "0", normal_cell)
            sheetEth.write(index, 8, network_type + str(int(line['NETWORK-ID'])), normal_cell)
            sheetEth.write(index, 9, line['FRAME-ID'], normal_cell)
            sheetEth.write(index, 10, line['DATA'], normal_cell)
            index = index + 1

    workbook.save(path + '\\' + os.path.splitext(tail)[0] + '.xls')
    print("Report file saved!")


def createSecondFile(head, tail, can_lin_data, eth_data):
    normal_cell = xlwt.easyxf('align: wrap on, vert center, horiz center;')
    excelFileName = head + "\\" + tail.split(".")[0] + ".xls"
    wb = xlrd.open_workbook(excelFileName, formatting_info=True)
    edit_wb = copy(wb)
    # compute the offset time, necessary in approximating time frames:
    sheet = wb.sheet_by_name('OFFSET DATA')
    average_log_time = 0
    count = 0
    for row_index in range(1, sheet.nrows):
        average_log_time = average_log_time + float(str(sheet.cell(row_index, 5).value).replace(",", "."))
        count = count + 1
    average_log_time = average_log_time / count
    average_calculated_time = 0
    count = 0
    for row_index in range(1, sheet.nrows):
        average_calculated_time = average_calculated_time + float(str(sheet.cell(row_index, 0).value).replace(",", "."))
        count = count + 1
    average_calculated_time = average_calculated_time / count
    offset = average_log_time - average_calculated_time

    # fill the offset in the ETH sheet
    eth_sheet = get_sheet_by_name(edit_wb, 'LOG ETH')
    for index in range(1, wb.sheet_by_name('LOG ETH').nrows):
        eth_sheet.write(index, 6, xlwt.Formula("AVERAGE('OFFSET DATA'!F$2:F$11)-AVERAGE('OFFSET DATA'!A$2:A$11)"), normal_cell)
        eth_sheet.write(index, 7, xlwt.Formula("G$2 + F" + str(index + 1)), normal_cell)
    # create and fill comparison sheet
    sheetComparison = edit_wb.add_sheet("COMPARISON", cell_overwrite_ok=True)
    sheetComparison.col(0).width = 256 * 15
    sheetComparison.col(1).width = 256 * 15
    sheetComparison.col(2).width = 256 * 15
    sheetComparison.col(3).width = 256 * 15
    sheetComparison.col(4).width = 256 * 15
    sheetComparison.col(5).width = 256 * 15
    sheetComparison.col(6).width = 256 * 15
    sheetComparison.col(7).width = 256 * 15
    sheetComparison.col(8).width = 256 * 15
    sheetComparison.col(9).width = 256 * 2
    sheetComparison.col(10).width = 256 * 15
    sheetComparison.col(11).width = 256 * 15
    sheetComparison.col(12).width = 256 * 15
    sheetComparison.col(13).width = 256 * 15
    sheetComparison.col(14).width = 256 * 15
    sheetComparison.write(0, 0, "comparison no.", normal_cell)
    sheetComparison.write(0, 1, "ETH Sequence Number", normal_cell)
    sheetComparison.write(0, 2, "ETH CAN-LIN Frame Number", normal_cell)
    sheetComparison.write(0, 3, "ETH CAN-LIN Frame Rank", normal_cell)
    sheetComparison.write(0, 4, "Calculated CAN-LIN Time", normal_cell)
    sheetComparison.write(0, 5, "ETH Time", normal_cell)
    sheetComparison.write(0, 6, "NMoE Bus Name", normal_cell)
    sheetComparison.write(0, 7, "ETH CAN-LIN FrameID", normal_cell)
    sheetComparison.write(0, 8, "ETH Data", normal_cell)
    sheetComparison.write(0, 9, "", normal_cell)
    sheetComparison.write(0, 10, "Log Time", normal_cell)
    sheetComparison.write(0, 11, "NMoE Bus Name", normal_cell)
    sheetComparison.write(0, 12, "Log FrameID", normal_cell)
    sheetComparison.write(0, 13, "Log Data", normal_cell)
    sheetComparison.write(0, 14, "Time Difference", normal_cell)
    index = 1
    for log in can_lin_data:
        sheetComparison.write(index, 0, index, normal_cell)
        sheetComparison.write(index, 10, str(log['TIMESTAMP']).replace(".", ","), normal_cell)
        sheetComparison.write(index, 11, log['NETWORK'], normal_cell)
        sheetComparison.write(index, 12, log['ID'], normal_cell)
        sheetComparison.write(index, 13, log['DATA'], normal_cell)
        sheetComparison.write(index, 14, xlwt.Formula("F" + str(index + 1) + "-K" + str(index + 1)), normal_cell)
        for eth in eth_data[:]:
            if approx_equal(offset + float(eth['TIME']) + float(eth['ETH-TIME']), float(log['TIMESTAMP']), tolerance=0.0002):
                #if (str(log['ID']).upper() == str(eth['FRAME-ID']).upper()) and (str(log['DATA']).upper() == str(eth['DATA']).upper()):
                if (str(log['DATA']).upper() == str(eth['DATA']).upper()):
                    sheetComparison.write(index, 1, eth['SEQUENCE-NUMBER'], normal_cell)
                    sheetComparison.write(index, 2, eth['FRAME-NUMBER'], normal_cell)
                    sheetComparison.write(index, 3, eth['RANK'], normal_cell)
                    sheetComparison.write(index, 4, str(round(float(eth['TIME']) + float(eth['ETH-TIME']), 3)).replace(".", ","), normal_cell)
                    sheetComparison.write(index, 5, xlwt.Formula("AVERAGE('OFFSET DATA'!F$2:F$11)-AVERAGE('OFFSET DATA'!A$2:A$11) + E" + str(index+1)), normal_cell)
                    if eth['NETWORK-TYPE'] == 1:
                        network_type = 'CAN'
                    elif eth['NETWORK-TYPE'] == 2:
                        network_type = 'LIN'
                    elif eth['NETWORK-TYPE'] == 3:
                        network_type = 'Ethernet'
                    else:
                        network_type = 'INVALID'
                    sheetComparison.write(index, 6, network_type + str(int(eth['NETWORK-ID'])), normal_cell)
                    sheetComparison.write(index, 7, eth['FRAME-ID'], normal_cell)
                    sheetComparison.write(index, 8, eth['DATA'], normal_cell)
                    eth_data.remove(eth)
                    break
        index = index + 1

    edit_wb.save(excelFileName)
    print("Report file saved!")


def approx_equal(x, y, tolerance=0.0001):
    return abs(x-y) <= 0.5 * tolerance * (x + y)


def arg_parse(parser):
    parser.add_argument('-in', '--input', help="input .asc file", required=True, default="")
    parser.add_argument('-config', '--config', help="input configuration file file", required=True, default="")
    parser.add_argument('-run1', action="store_const", const="-run1", help="execute only the first step of trace analysis", required=False, default="")
    parser.add_argument('-run2', action="store_const", const="-run2", help="execute the second step of trace analysis", required=False, default="")


def main():
    # parsing the command line arguments
    first_run = False
    second_run = False
    parser = argparse.ArgumentParser()
    arg_parse(parser)
    args = parser.parse_args()
    input_file_path = args.input
    head, tail = ntpath.split(input_file_path)
    config_file_path = args.config
    if args.run1:
        first_run = True
    if args.run2:
        second_run = True
    if first_run and second_run:
        print("Tool cannot execute the both steps in a single run!\nPlease select the appropriate generation step.")
        sys.exit(1)
    if not first_run and not second_run:
        print("The generation step must be specified.")
        sys.exit(1)

    #parse the input files and get relevant data
    configuration, network_list = checkConfig(config_file_path)
    content = filterData(readFile(input_file_path))
    linMsgs, canMsgs, ethMsgs = sortData(content, network_list)

    if first_run:
        can_data = checkCan(canMsgs, network_list)
        lin_data = checkLin(linMsgs, network_list)
        can_lin_data = can_data + lin_data
        can_lin_data = sorted(can_lin_data, key=lambda x: x['TIMESTAMP'])
        eth_data = checkEthernet(ethMsgs, configuration)
        createFirstFile(head, tail, can_lin_data, eth_data)


    if second_run:
        can_data = checkCan(canMsgs, network_list)
        lin_data = checkLin(linMsgs, network_list)
        can_lin_data = can_data + lin_data
        can_lin_data = sorted(can_lin_data, key=lambda x: x['TIMESTAMP'])
        eth_data = checkEthernet(ethMsgs, configuration)
        createSecondFile(head, tail, can_lin_data, eth_data)


if __name__ == "__main__":
    main()